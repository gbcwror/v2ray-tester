package cfcheck

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const cfIPFile = "cloudflare-ips.txt"

type Checker struct {
	ranges []*net.IPNet
}

func New(cfURL string) *Checker {
	data := download(cfURL)

	if data == "" {
		data = loadLocal()
	}

	if data == "" {
		log.Println("Warning: No Cloudflare IP ranges available. CF separation disabled.")
		return nil
	}

	ranges := parseRanges(data)
	if len(ranges) == 0 {
		log.Println("Warning: No valid CIDR ranges parsed. CF separation disabled.")
		return nil
	}

	log.Printf("Loaded %d Cloudflare IP ranges", len(ranges))
	return &Checker{ranges: ranges}
}

func download(cfURL string) string {
	if cfURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cfURL)
	if err != nil {
		log.Printf("Warning: Failed to download Cloudflare IPs: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Warning: Cloudflare IPs download returned status %d", resp.StatusCode)
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Warning: Failed to read Cloudflare IPs response: %v", err)
		return ""
	}

	data := strings.TrimSpace(string(body))
	if data == "" {
		return ""
	}

	if err := os.WriteFile(cfIPFile, []byte(data+"\n"), 0644); err != nil {
		log.Printf("Warning: Failed to save %s: %v", cfIPFile, err)
	}

	return data
}

func loadLocal() string {
	body, err := os.ReadFile(cfIPFile)
	if err != nil {
		return ""
	}
	data := strings.TrimSpace(string(body))
	if data != "" {
		log.Printf("Using existing %s", cfIPFile)
	}
	return data
}

func parseRanges(data string) []*net.IPNet {
	var ranges []*net.IPNet
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			line = line + "/32"
		}
		_, cidr, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ranges = append(ranges, cidr)
	}
	return ranges
}

func (c *Checker) IsCloudflareIP(address string) bool {
	if c == nil {
		return false
	}

	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range c.ranges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Checker) Enabled() bool {
	return c != nil && len(c.ranges) > 0
}

func ExtractAddress(link string) string {
	link = strings.TrimSpace(link)

	if strings.HasPrefix(link, "vmess://") {
		return extractVMessAddress(link)
	}

	if strings.HasPrefix(link, "ss://") {
		return extractSSAddress(link)
	}

	for _, prefix := range []string{
		"vless://", "trojan://",
		"hysteria2://", "hy2://",
		"wireguard://", "wg://",
	} {
		if strings.HasPrefix(link, prefix) {
			return extractURLAddress(link)
		}
	}

	return ""
}

func extractURLAddress(link string) string {
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	atIdx := strings.Index(link, "@")
	if atIdx < 0 {
		return ""
	}
	server := link[atIdx+1:]
	if i := strings.Index(server, "?"); i >= 0 {
		server = server[:i]
	}
	if strings.HasPrefix(server, "[") {
		end := strings.Index(server, "]")
		if end >= 0 {
			return server[1:end]
		}
		return ""
	}
	if i := strings.LastIndex(server, ":"); i >= 0 {
		return server[:i]
	}
	return server
}

func extractVMessAddress(link string) string {
	raw := link[len("vmess://"):]
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}

	decoded, err := b64Decode(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}

	var m map[string]any
	if err := json.Unmarshal(decoded, &m); err != nil {
		return ""
	}

	if addr, ok := m["add"].(string); ok {
		return addr
	}
	return ""
}

func extractSSAddress(link string) string {
	raw := link[len("ss://"):]
	if i := strings.LastIndex(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}

	if atIdx := strings.LastIndex(raw, "@"); atIdx >= 0 {
		server := raw[atIdx+1:]
		return hostFromServer(server)
	}

	decoded, err := b64Decode(raw)
	if err != nil {
		return ""
	}
	s := string(decoded)
	if atIdx := strings.LastIndex(s, "@"); atIdx >= 0 {
		server := s[atIdx+1:]
		return hostFromServer(server)
	}
	return ""
}

func hostFromServer(server string) string {
	if strings.HasPrefix(server, "[") {
		end := strings.Index(server, "]")
		if end >= 0 {
			return server[1:end]
		}
		return ""
	}
	if i := strings.LastIndex(server, ":"); i >= 0 {
		return server[:i]
	}
	return server
}

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	padLen := (4 - len(s)%4) % 4
	padded := s + strings.Repeat("=", padLen)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(padded); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}