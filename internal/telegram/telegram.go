package telegram

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var proxyLinkPattern = regexp.MustCompile(
	`(?i)(vless|vmess|ss|trojan|hysteria2|hy2|wireguard|wg)://[^\s<>"'\x60]+`,
)

var linkSplitter = regexp.MustCompile(
	`(?i)(://[^\s]+?)((?:vless|vmess|ss|trojan|hysteria2|hy2|wireguard|wg)://)`,
)

var htmlTagPattern = regexp.MustCompile(`<[^>]*>`)

type Config struct {
	MaxAgeDays   int
	MaxPages     int
	RequestDelay time.Duration
	Workers      int
}

type channelMessage struct {
	id      int
	date    time.Time
	links   []string
	channel string
}

type channelResult struct {
	channel           string
	messagesScanned   int
	messagesWithLinks int
	links             []string
	pages             int
	duration          time.Duration
	err               error
}

func LoadChannels(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var channels []string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := normalizeChannel(line)
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		channels = append(channels, name)
	}
	return channels
}

func normalizeChannel(input string) string {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "@")

	lower := strings.ToLower(s)
	for _, prefix := range []string{
		"https://telegram.dog/s/",
		"https://telegram.dog/",
		"https://telegram.me/s/",
		"https://telegram.me/",
		"https://t.me/s/",
		"https://t.me/",
		"http://telegram.dog/s/",
		"http://telegram.dog/",
		"http://telegram.me/s/",
		"http://telegram.me/",
		"http://t.me/s/",
		"http://t.me/",
		"telegram.dog/s/",
		"telegram.dog/",
		"telegram.me/s/",
		"telegram.me/",
		"t.me/s/",
		"t.me/",
	} {
		if strings.HasPrefix(lower, prefix) {
			s = s[len(prefix):]
			break
		}
	}

	s = strings.TrimRight(s, "/")
	s = strings.TrimSpace(s)

	if strings.Contains(s, "/") || strings.Contains(s, "?") || s == "" {
		return ""
	}

	return s
}

func ScrapeAll(channels []string, cfg Config) []string {
	if len(channels) == 0 {
		return nil
	}

	log.Printf("Scraping %d Telegram channel(s) (last %d days)...", len(channels), cfg.MaxAgeDays)

	results := make([]channelResult, len(channels))
	sem := make(chan struct{}, cfg.Workers)
	var wg sync.WaitGroup

	for i, ch := range channels {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, channel string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = scrapeChannel(channel, cfg)
		}(i, ch)
	}

	wg.Wait()

	var allLinks []string
	totalLinks := 0

	for _, r := range results {
		if r.err != nil {
			log.Printf("  %-60s -> FAILED: %v", truncate(r.channel, 60), r.err)
			continue
		}
		log.Printf("  %-60s -> %d link(s), %d pages, %d msgs, %s",
			truncate(r.channel, 60),
			len(r.links),
			r.pages,
			r.messagesScanned,
			r.duration.Round(time.Millisecond),
		)
		allLinks = append(allLinks, r.links...)
		totalLinks += len(r.links)
	}

	log.Printf("Telegram total: %d", totalLinks)
	return allLinks
}

func scrapeChannel(channel string, cfg Config) channelResult {
	start := time.Now()
	result := channelResult{channel: channel}

	cutoff := time.Now().UTC().AddDate(0, 0, -cfg.MaxAgeDays)
	client := &http.Client{Timeout: 30 * time.Second}
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"

	var allLinks []string
	messagesScanned := 0
	messagesWithLinks := 0
	beforeID := 0

	for page := 1; page <= cfg.MaxPages; page++ {
		result.pages = page

		pageURL := fmt.Sprintf("https://t.me/s/%s", channel)
		if beforeID > 0 {
			pageURL = fmt.Sprintf("https://t.me/s/%s?before=%d", channel, beforeID)
		}

		messages, err := fetchPage(client, pageURL, channel, userAgent)
		if err != nil {
			if page == 1 {
				result.err = err
				result.duration = time.Since(start)
				return result
			}
			break
		}

		if len(messages) == 0 {
			break
		}

		reachedCutoff := false
		for _, msg := range messages {
			if msg.date.Before(cutoff) {
				reachedCutoff = true
				continue
			}
			messagesScanned++
			if len(msg.links) > 0 {
				messagesWithLinks++
				allLinks = append(allLinks, msg.links...)
			}
		}

		if reachedCutoff {
			break
		}

		oldestOnPage := messages[len(messages)-1]
		beforeID = oldestOnPage.id
		if beforeID <= 1 {
			break
		}

		if page < cfg.MaxPages {
			time.Sleep(cfg.RequestDelay)
		}
	}

	result.messagesScanned = messagesScanned
	result.messagesWithLinks = messagesWithLinks
	result.links = allLinks
	result.duration = time.Since(start)
	return result
}

func fetchPage(client *http.Client, pageURL, channel, userAgent string) ([]channelMessage, error) {
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}

	return extractMessages(doc, channel)
}

func extractMessages(doc *goquery.Document, channel string) ([]channelMessage, error) {
	var messages []channelMessage

	doc.Find(".js-widget_message_wrap").Each(func(i int, wrap *goquery.Selection) {
		msg := channelMessage{channel: channel}

		widget := wrap.Find("[data-post]").First()
		if widget.Length() == 0 {
			return
		}

		dataPost, exists := widget.Attr("data-post")
		if !exists {
			return
		}
		parts := strings.SplitN(dataPost, "/", 2)
		if len(parts) != 2 {
			return
		}
		id, err := strconv.Atoi(parts[1])
		if err != nil {
			return
		}
		msg.id = id

		var foundDate bool
		wrap.Find("time").Each(func(_ int, t *goquery.Selection) {
			if foundDate {
				return
			}
			datetime, exists := t.Attr("datetime")
			if !exists {
				return
			}
			for _, layout := range []string{
				time.RFC3339,
				"2006-01-02T15:04:05-07:00",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05+00:00",
			} {
				if parsed, err := time.Parse(layout, datetime); err == nil {
					msg.date = parsed.UTC()
					foundDate = true
					return
				}
			}
		})

		if msg.date.IsZero() {
			return
		}

		linkMap := make(map[string]string)

		wrap.Find(".tgme_widget_message_text, .js-message_text").Each(func(_ int, el *goquery.Selection) {
			html, err := el.Html()
			if err != nil {
				html = el.Text()
			}
			html = strings.ReplaceAll(html, "<br>", "\n")
			html = strings.ReplaceAll(html, "<br/>", "\n")
			html = strings.ReplaceAll(html, "<br />", "\n")
			cleaned := htmlTagPattern.ReplaceAllString(html, "\n")
			cleaned = decodeHTMLEntities(cleaned)
			cleaned = linkSplitter.ReplaceAllString(cleaned, "$1\n$2")
			extractLinksInto(cleaned, linkMap)
		})

		wrap.Find("code, pre").Each(func(_ int, el *goquery.Selection) {
			html, err := el.Html()
			if err != nil {
				html = el.Text()
			}
			html = strings.ReplaceAll(html, "<br>", "\n")
			html = strings.ReplaceAll(html, "<br/>", "\n")
			html = strings.ReplaceAll(html, "<br />", "\n")
			cleaned := htmlTagPattern.ReplaceAllString(html, "\n")
			cleaned = decodeHTMLEntities(cleaned)
			cleaned = linkSplitter.ReplaceAllString(cleaned, "$1\n$2")
			extractLinksInto(cleaned, linkMap)
		})

		wrap.Find("a[href]").Each(func(_ int, a *goquery.Selection) {
			href, _ := a.Attr("href")
			href = decodeHTMLEntities(strings.TrimSpace(href))
			link := cleanLink(href)
			if link != "" {
				normKey := normalizeKey(link)
				if _, exists := linkMap[normKey]; !exists {
					linkMap[normKey] = link
				}
			}
		})

		for _, link := range linkMap {
			msg.links = append(msg.links, link)
		}

		messages = append(messages, msg)
	})

	for i := 0; i < len(messages); i++ {
		for j := i + 1; j < len(messages); j++ {
			if messages[j].id > messages[i].id {
				messages[i], messages[j] = messages[j], messages[i]
			}
		}
	}

	return messages, nil
}

func extractLinksInto(text string, linkMap map[string]string) {
	text = linkSplitter.ReplaceAllString(text, "$1\n$2")
	matches := proxyLinkPattern.FindAllString(text, -1)
	for _, m := range matches {
		link := cleanLink(m)
		if link == "" {
			continue
		}
		normKey := normalizeKey(link)
		if _, exists := linkMap[normKey]; !exists {
			linkMap[normKey] = link
		}
	}
}

func normalizeKey(link string) string {
	if idx := strings.LastIndex(link, "#"); idx > 0 {
		return strings.ToLower(link[:idx])
	}
	return strings.ToLower(link)
}

func cleanLink(link string) string {
	link = strings.TrimSpace(link)
	link = htmlTagPattern.ReplaceAllString(link, "")
	link = decodeHTMLEntities(link)

	for _, suffix := range []string{"<", ">", "\"", "`", ")", "}"} {
		if i := strings.Index(link, suffix); i > 0 {
			link = link[:i]
		}
	}

	link = strings.TrimRight(link, ".,;!?")

	valid := false
	for _, prefix := range []string{
		"vless://", "vmess://", "ss://", "trojan://",
		"hysteria2://", "hy2://", "wireguard://", "wg://",
	} {
		if strings.HasPrefix(strings.ToLower(link), prefix) {
			valid = true
			break
		}
	}
	if !valid {
		return ""
	}

	return link
}

func decodeHTMLEntities(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&#33;", "!")
	s = strings.ReplaceAll(s, "&#38;", "&")
	s = strings.ReplaceAll(s, "&#61;", "=")
	s = strings.ReplaceAll(s, "&#43;", "+")
	s = strings.ReplaceAll(s, "&#47;", "/")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}