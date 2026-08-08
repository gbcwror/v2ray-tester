package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"v2ray-tester/internal/cfcheck"
	"v2ray-tester/internal/converter"
	"v2ray-tester/internal/fetcher"
	"v2ray-tester/internal/output"
	"v2ray-tester/internal/telegram"
	"v2ray-tester/internal/tester"
)

type Config struct {
	Subscriptions       string `json:"subscriptions"`
	Channels            string `json:"channels"`
	ChannelMaxAgeDays   int    `json:"channel_max_age_days"`
	ChannelMaxPages     int    `json:"channel_max_pages"`
	ChannelRequestDelay int    `json:"channel_request_delay_ms"`
	ChannelConcurrent   int    `json:"channel_concurrent"`
	TestURL             string `json:"test_url"`
	Timeout             int    `json:"timeout"`
	Concurrent          int    `json:"concurrent"`
	PerFile             int    `json:"per_file"`
	OutputDir           string `json:"output_dir"`
	ReportFile          string `json:"report_file"`
	CloudflareURL       string `json:"cloudflare_ips_url"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		Subscriptions:       "subscription.txt",
		Channels:            "channels.txt",
		ChannelMaxAgeDays:   14,
		ChannelMaxPages:     50,
		ChannelRequestDelay: 500,
		ChannelConcurrent:   10,
		TestURL:             "http://gstatic.com/generate_204",
		Timeout:             5,
		Concurrent:          300,
		PerFile:             500,
		OutputDir:           "configs",
		ReportFile:          "REPORT.md",
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
	repoURL := flag.String("repo-url", "", "Repository base URL for report links")
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

	var channelLinks []string
	channels := telegram.LoadChannels(cfg.Channels)
	if len(channels) > 0 {
		tgCfg := telegram.Config{
			MaxAgeDays:   cfg.ChannelMaxAgeDays,
			MaxPages:     cfg.ChannelMaxPages,
			RequestDelay: time.Duration(cfg.ChannelRequestDelay) * time.Millisecond,
			Workers:      cfg.ChannelConcurrent,
		}
		channelLinks = telegram.ScrapeAll(channels, tgCfg)
		fmt.Println()
	} else {
		log.Println("No active Telegram channels. Skipping channel scraping.")
		fmt.Println()
	}

	var subLinks []string
	subLinks, err = fetcher.FetchAll(cfg.Subscriptions)
	if err != nil {
		if len(channelLinks) == 0 {
			log.Fatalf("Fetch error: %v", err)
		}
		log.Printf("Subscription fetch warning: %v", err)
	}
	fmt.Println()

	allLinks := append(channelLinks, subLinks...)

	if len(allLinks) == 0 {
		log.Fatal("Error: No configs fetched from any source")
	}
	log.Printf("Total fetched: %d (channels: %d, subscriptions: %d)", len(allLinks), len(channelLinks), len(subLinks))

	allLinks = converter.Deduplicate(allLinks)
	log.Printf("After dedup: %d", len(allLinks))

	supported := make([]string, 0, len(allLinks))
	skipped := 0
	for _, l := range allLinks {
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