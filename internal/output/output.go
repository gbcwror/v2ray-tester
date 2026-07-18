package output

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"v2ray-tester/internal/cfcheck"
	"v2ray-tester/internal/converter"
	"v2ray-tester/internal/tester"
)

var protocolOrder = []string{"vless", "vmess", "ss", "trojan", "hysteria2", "wireguard"}
var protocolDisplay = map[string]string{
	"vless":      "VLESS",
	"vmess":      "VMess",
	"ss":         "Shadowsocks",
	"trojan":     "Trojan",
	"hysteria2":  "Hysteria2",
	"wireguard":  "WireGuard",
	"cloudflare": "Cloudflare",
}

type FileInfo struct {
	Index int
	Count int
	Path  string
}

func SaveResults(results []tester.Result, perFile int, outputDir string, cfChecker *cfcheck.Checker) (map[string][]FileInfo, error) {
	byProto := make(map[string][]tester.Result)
	var cfResults []tester.Result

	for _, r := range results {
		if r.DelayMs <= 0 {
			continue
		}
		p := converter.GetProtocol(r.Link)
		if p == "unknown" {
			continue
		}

		if cfChecker.Enabled() {
			addr := cfcheck.ExtractAddress(r.Link)
			if addr != "" && cfChecker.IsCloudflareIP(addr) {
				cfResults = append(cfResults, r)
				continue
			}
		}

		byProto[p] = append(byProto[p], r)
	}

	for p := range byProto {
		sort.Slice(byProto[p], func(i, j int) bool {
			return byProto[p][i].DelayMs < byProto[p][j].DelayMs
		})
	}
	sort.Slice(cfResults, func(i, j int) bool {
		return cfResults[i].DelayMs < cfResults[j].DelayMs
	})

	for _, p := range protocolOrder {
		_ = os.RemoveAll(filepath.Join(outputDir, p))
	}
	_ = os.RemoveAll(filepath.Join(outputDir, "cloudflare"))

	fileInfo := make(map[string][]FileInfo)
	total := 0

	for _, p := range protocolOrder {
		items, ok := byProto[p]
		if !ok {
			continue
		}
		written, err := writeChunks(items, p, p, perFile, outputDir)
		if err != nil {
			return nil, err
		}
		fileInfo[p] = written
		total += len(items)
		log.Printf("  %s/%s/: %d config(s) in %d file(s)", outputDir, p, len(items), len(written))
	}

	if len(cfResults) > 0 {
		written, err := writeChunks(cfResults, "cloudflare", "cf", perFile, outputDir)
		if err != nil {
			return nil, err
		}
		fileInfo["cloudflare"] = written
		total += len(cfResults)
		log.Printf("  %s/cloudflare/: %d config(s) in %d file(s)", outputDir, len(cfResults), len(written))
	}

	log.Printf("Total working: %d", total)
	return fileInfo, nil
}

func writeChunks(items []tester.Result, dirName, filePrefix string, perFile int, outputDir string) ([]FileInfo, error) {
	dir := filepath.Join(outputDir, dirName)
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

	var info []FileInfo
	for idx, chunk := range chunks {
		fname := fmt.Sprintf("%s-%d.txt", filePrefix, idx+1)
		fpath := filepath.Join(dir, fname)
		var sb strings.Builder
		for _, r := range chunk {
			sb.WriteString(r.Link)
			sb.WriteByte('\n')
		}
		if err := os.WriteFile(fpath, []byte(sb.String()), 0644); err != nil {
			return nil, err
		}
		info = append(info, FileInfo{
			Index: idx + 1,
			Count: len(chunk),
			Path:  filepath.ToSlash(filepath.Join(outputDir, dirName, fname)),
		})
	}
	return info, nil
}

func GenerateReport(fileInfo map[string][]FileInfo, repoURL string, reportFile string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	var sb strings.Builder

	sb.WriteString("# v2ray Config Collector\n\nAuto-tested proxy configurations, updated every 12 hours.\n\n")
	sb.WriteString(fmt.Sprintf("> Last update: %s\n\n---\n\n## Statistics\n\n", now))
	sb.WriteString("| Protocol | Working Configs | Files |\n|:--------:|:---------------:|:-----:|\n")

	allKeys := append([]string{}, protocolOrder...)
	if _, ok := fileInfo["cloudflare"]; ok {
		allKeys = append(allKeys, "cloudflare")
	}

	totalC, totalF := 0, 0
	for _, p := range allKeys {
		files, ok := fileInfo[p]
		if !ok {
			continue
		}
		c := 0
		for _, f := range files {
			c += f.Count
		}
		name := protocolDisplay[p]
		sb.WriteString(fmt.Sprintf("| %s | %d | %d |\n", name, c, len(files)))
		totalC += c
		totalF += len(files)
	}
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d** |\n\n---\n\n## Subscription Links\n", totalC, totalF))

	for _, p := range allKeys {
		files, ok := fileInfo[p]
		if !ok {
			continue
		}
		name := protocolDisplay[p]
		sb.WriteString(fmt.Sprintf("\n### %s\n\n", name))
		for _, f := range files {
			link := f.Path
			if repoURL != "" {
				link = fmt.Sprintf("%s/%s", strings.TrimRight(repoURL, "/"), f.Path)
			}
			sb.WriteString(fmt.Sprintf("> %s %d (%d configs)\n```\n%s\n```\n\n",
				name, f.Index, f.Count, link))
		}
	}

	return os.WriteFile(reportFile, []byte(sb.String()), 0644)
}