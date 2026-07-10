package output

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"v2ray-tester/internal/converter"
	"v2ray-tester/internal/tester"
)

var protocolOrder = []string{"vless", "vmess", "ss", "trojan", "hysteria2", "wireguard"}
var protocolDisplay = map[string]string{
	"vless":     "VLESS",
	"vmess":     "VMess",
	"ss":        "Shadowsocks",
	"trojan":    "Trojan",
	"hysteria2": "Hysteria2",
	"wireguard": "WireGuard",
}

type FileInfo struct {
	Index int
	Count int
	Path  string
}

func SaveResults(results []tester.Result, perFile int, outputDir string) (map[string][]FileInfo, error) {
	byProto := make(map[string][]tester.Result)
	for _, r := range results {
		if r.DelayMs <= 0 {
			continue
		}
		p := converter.GetProtocol(r.Link)
		if p == "unknown" {
			continue
		}
		byProto[p] = append(byProto[p], r)
	}

	for p := range byProto {
		sort.Slice(byProto[p], func(i, j int) bool {
			return byProto[p][i].DelayMs < byProto[p][j].DelayMs
		})
	}

	for _, p := range protocolOrder {
		_ = os.RemoveAll(filepath.Join(outputDir, p))
	}

	fileInfo := make(map[string][]FileInfo)
	total := 0

	for _, p := range protocolOrder {
		items, ok := byProto[p]
		if !ok {
			continue
		}
		dir := filepath.Join(outputDir, p)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
		var chunks [][]tester.Result
		for i := 0; i < len(items); i += perFile {
			end := i + perFile
			if end > len(items) {
				end = len(items)
			}
			chunks = append(chunks, items[i:end])
		}
		for idx, chunk := range chunks {
			fname := fmt.Sprintf("%s-%d.txt", p, idx+1)
			fpath := filepath.Join(dir, fname)
			var sb strings.Builder
			for _, r := range chunk {
				sb.WriteString(r.Link)
				sb.WriteByte('\n')
			}
			if err := os.WriteFile(fpath, []byte(sb.String()), 0644); err != nil {
				return nil, err
			}
			fileInfo[p] = append(fileInfo[p], FileInfo{
				Index: idx + 1,
				Count: len(chunk),
				Path:  filepath.ToSlash(filepath.Join(outputDir, p, fname)),
			})
		}
		total += len(items)
		log.Printf("  %s/%s/: %d config(s) in %d file(s)", outputDir, p, len(items), len(chunks))
	}

	log.Printf("Total working: %d", total)
	return fileInfo, nil
}

func GenerateReadme(fileInfo map[string][]FileInfo, repoURL string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	var sb strings.Builder

	sb.WriteString("# v2ray Config Collector\n\nAuto-tested proxy configurations, updated every 12 hours.\n\n")
	sb.WriteString(fmt.Sprintf("> Last update: %s\n\n---\n\n## Statistics\n\n", now))
	sb.WriteString("| Protocol | Working Configs | Files |\n|:--------:|:---------------:|:-----:|\n")

	totalC, totalF := 0, 0
	for _, p := range protocolOrder {
		files, ok := fileInfo[p]
		if !ok {
			continue
		}
		c := 0
		for _, f := range files {
			c += f.Count
		}
		sb.WriteString(fmt.Sprintf("| %s | %d | %d |\n", protocolDisplay[p], c, len(files)))
		totalC += c
		totalF += len(files)
	}
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d** |\n\n---\n\n## Subscription Links\n", totalC, totalF))

	for _, p := range protocolOrder {
		files, ok := fileInfo[p]
		if !ok {
			continue
		}
		name := protocolDisplay[p]
		sb.WriteString(fmt.Sprintf("\n### %s\n\n", name))
		for _, f := range files {
			sb.WriteString(fmt.Sprintf("> %s %d (%d configs)\n```\n%s/%s\n```\n\n",
				name, f.Index, f.Count, strings.TrimRight(repoURL, "/"), f.Path))
		}
	}

	return os.WriteFile("README.md", []byte(sb.String()), 0644)
}