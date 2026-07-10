package fetcher

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var supportedPrefixes = []string{
	"vless://", "vmess://", "ss://", "trojan://",
	"hy2://", "hysteria2://", "wireguard://", "wg://",
}

func FetchAll(subFile string) ([]string, error) {
	data, err := os.ReadFile(subFile)
	if err != nil {
		return nil, fmt.Errorf("reading subscription file: %w", err)
	}

	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in subscription file")
	}

	log.Printf("Fetching %d subscription(s)...", len(urls))
	client := &http.Client{Timeout: 30 * time.Second}

	var all []string
	for _, url := range urls {
		links, err := fetchOne(client, url)
		if err != nil {
			log.Printf("  %-60s -> FAILED: %v", truncate(url, 60), err)
			continue
		}
		log.Printf("  %-60s -> %d config(s)", truncate(url, 60), len(links))
		all = append(all, links...)
	}
	return all, nil
}

func fetchOne(client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2rayN/6.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(body))

	if !containsSupportedPrefix(raw) {
		if decoded, ok := tryBase64Decode(raw); ok {
			raw = decoded
		}
	}

	var links []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, p := range supportedPrefixes {
			if strings.HasPrefix(line, p) {
				links = append(links, line)
				break
			}
		}
	}
	return links, nil
}

func containsSupportedPrefix(s string) bool {
	for _, p := range supportedPrefixes {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func tryBase64Decode(text string) (string, bool) {
	text = strings.TrimSpace(text)
	padLen := (4 - len(text)%4) % 4
	padded := text + strings.Repeat("=", padLen)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(padded); err == nil {
			s := string(b)
			if containsSupportedPrefix(s) {
				return s, true
			}
		}
	}
	return "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}