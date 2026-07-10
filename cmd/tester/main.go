package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"v2ray-tester/internal/converter"
	"v2ray-tester/internal/fetcher"
	"v2ray-tester/internal/output"
	"v2ray-tester/internal/tester"
)

func main() {
	subscriptions := flag.String("subscriptions", "subscription.txt", "Path to subscription file")
	testURL := flag.String("test-url", "http://gstatic.com/generate_204", "URL to test connectivity")
	timeoutSec := flag.Int("timeout", 5, "Test timeout in seconds")
	concurrent := flag.Int("concurrent", 200, "Number of concurrent tests")
	perFile := flag.Int("per-file", 500, "Configs per output file")
	repoURL := flag.String("repo-url", "", "Repository base URL for README links")
	outputDir := flag.String("output-dir", "protocols", "Output directory")
	flag.Parse()

	if *repoURL == "" {
		log.Fatal("Error: --repo-url is required")
	}

	log.SetFlags(0)
	log.Printf("v2ray Config Tester (Go, in-process Xray)")
	log.Printf("Go %s | %s/%s | Concurrency=%d | Timeout=%ds",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, *concurrent, *timeoutSec)
	fmt.Println()

	links, err := fetcher.FetchAll(*subscriptions)
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

	results := tester.TestAll(supported, *testURL, *timeoutSec, *concurrent)

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

	fileInfo, err := output.SaveResults(results, *perFile, *outputDir)
	if err != nil {
		log.Fatalf("Save error: %v", err)
	}
	if err := output.GenerateReadme(fileInfo, *repoURL); err != nil {
		log.Fatalf("README error: %v", err)
	}
}