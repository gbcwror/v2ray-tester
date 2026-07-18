package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"v2ray-tester/internal/cfcheck"
	"v2ray-tester/internal/converter"
	"v2ray-tester/internal/fetcher"
	"v2ray-tester/internal/output"
	"v2ray-tester/internal/tester"
)

type Config struct {
	Subscriptions  string `json:"subscriptions"`
	TestURL        string `json:"test_url"`
	Timeout        int    `json:"timeout"`
	Concurrent     int    `json:"concurrent"`
	PerFile        int    `json:"per_file"`
	OutputDir      string `json:"output_dir"`
	ReportFile     string `json:"report_file"`
	CloudflareURL  string `json:"cloudflare_ips_url"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		Subscriptions: "subscription.txt",
		TestURL:       "http://gstatic.com/generate_204",
		Timeout:       5,
		Concurrent:    300,
		PerFile:       500,
		OutputDir:     "configs",
		ReportFile:    "REPORT.md",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	repoURL := flag.String("repo-url", "", "Repository base URL for report links (optional)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	log.SetFlags(0)
	log.Printf("v2ray Config Tester (Go, in-process Xray)")
	log.Printf("Go %s | %s/%s | Concurrency=%d | Timeout=%ds",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, cfg.Concurrent, cfg.Timeout)
	fmt.Println()

	cfChecker := cfcheck.New(cfg.CloudflareURL)
	fmt.Println()

	links, err := fetcher.FetchAll(cfg.Subscriptions)
	if err != nil {
		log.Fatalf("Fetch error: %v", err)
	}
	if len(links) == 0 {
		log.Fatal("Error: No configs fetched")
	}
	log.Printf("Total fetched: %d", len(links))

	links = converter.Deduplicate(links)
	log.Printf("After dedup: %d", len(links))

	supported := make([]string, 0, len(links))
	skipped := 0
	for _, l := range links {
		if converter.GetProtocol(l) != "unknown" {
			supported = append(supported, l)
		} else {
			skipped++
		}
	}
	if skipped > 0 {
		log.Printf("Skipped %d unsupported link(s)", skipped)
	}
	if len(supported) == 0 {
		log.Fatal("Error: No supported configs to test")
	}
	fmt.Println()

	results := tester.TestAll(supported, cfg.TestURL, cfg.Timeout, cfg.Concurrent)

	working, failed := 0, 0
	for _, r := range results {
		if r.DelayMs > 0 {
			working++
		} else {
			failed++
		}
	}
	log.Printf("Results: %d working, %d failed", working, failed)
	fmt.Println()

	if working == 0 {
		log.Println("No working configs. Keeping existing output.")
		os.Exit(0)
	}

	fileInfo, err := output.SaveResults(results, cfg.PerFile, cfg.OutputDir, cfChecker)
	if err != nil {
		log.Fatalf("Save error: %v", err)
	}
	if err := output.GenerateReport(fileInfo, *repoURL, cfg.ReportFile); err != nil {
		log.Fatalf("Report error: %v", err)
	}
}