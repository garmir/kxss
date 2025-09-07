package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	concurrency  int
	timeout      time.Duration
	insecure     bool
	verbose      bool
	userAgent    string
	maxRedirects int
	maxSize      int64
	checkDOM     bool
	checkJS      bool
}

var config Config

type paramCheck struct {
	url   string
	param string
	value string
}

type result struct {
	url       string
	param     string
	character string
	context   string
}

func init() {
	flag.IntVar(&config.concurrency, "c", 40, "Number of concurrent workers")
	flag.DurationVar(&config.timeout, "t", 10*time.Second, "Request timeout")
	flag.BoolVar(&config.insecure, "insecure", false, "Skip SSL certificate verification")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output")
	flag.StringVar(&config.userAgent, "ua", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36", "User-Agent header")
	flag.IntVar(&config.maxRedirects, "max-redirects", 0, "Maximum redirects to follow (0 = no redirects)")
	flag.Int64Var(&config.maxSize, "max-size", 10*1024*1024, "Maximum response size (10MB default)")
	flag.BoolVar(&config.checkDOM, "dom", true, "Check for DOM-based XSS patterns")
	flag.BoolVar(&config.checkJS, "js", true, "Check for JS context injections")
}

func main() {
	flag.Parse()

	// Create HTTP client
	client := createHTTPClient()

	// Create channels for pipeline
	urls := make(chan string, config.concurrency)
	initialChecks := make(chan paramCheck, config.concurrency)
	reflectedParams := make(chan paramCheck, config.concurrency)
	results := make(chan result, config.concurrency)

	ctx := context.Background()
	var wg sync.WaitGroup

	// Stage 1: Read URLs
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				urls <- url
			}
		}
		close(urls)
	}()

	// Stage 2: Extract and check reflected parameters
	wg.Add(config.concurrency / 4)
	for i := 0; i < config.concurrency/4; i++ {
		go func() {
			defer wg.Done()
			for url := range urls {
				checkReflectedParams(ctx, client, url, initialChecks)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(initialChecks)
	}()

	// Stage 3: Test with canary string
	var wg2 sync.WaitGroup
	wg2.Add(config.concurrency / 2)
	for i := 0; i < config.concurrency/2; i++ {
		go func() {
			defer wg2.Done()
			for check := range initialChecks {
				if testCanary(ctx, client, check) {
					reflectedParams <- check
				}
			}
		}()
	}

	go func() {
		wg2.Wait()
		close(reflectedParams)
	}()

	// Stage 4: Test XSS characters
	var wg3 sync.WaitGroup
	wg3.Add(config.concurrency)
	for i := 0; i < config.concurrency; i++ {
		go func() {
			defer wg3.Done()
			for check := range reflectedParams {
				testXSSCharacters(ctx, client, check, results)
			}
		}()
	}

	go func() {
		wg3.Wait()
		close(results)
	}()

	// Print results
	for r := range results {
		fmt.Printf("[XSS] %s | param: %s | char: %s", r.url, r.param, r.character)
		if r.context != "" {
			fmt.Printf(" | context: %s", r.context)
		}
		fmt.Println()
	}
}

func createHTTPClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        config.concurrency,
		MaxIdleConnsPerHost: config.concurrency,
		MaxConnsPerHost:     config.concurrency,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.insecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   config.timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives: false,
		IdleConnTimeout:   90 * time.Second,
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if config.maxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= config.maxRedirects {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
		Timeout:       config.timeout,
	}
}

func checkReflectedParams(ctx context.Context, client *http.Client, targetURL string, output chan<- paramCheck) {
	u, err := url.Parse(targetURL)
	if err != nil {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "Error parsing URL %s: %v\n", targetURL, err)
		}
		return
	}

	// Skip if no query parameters
	if u.RawQuery == "" {
		return
	}

	body, err := fetchURL(ctx, client, targetURL)
	if err != nil {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "Error fetching %s: %v\n", targetURL, err)
		}
		return
	}

	// Check each parameter value for reflection
	for key, values := range u.Query() {
		for _, value := range values {
			if value == "" {
				continue
			}

			// Check if parameter value is reflected in response
			if strings.Contains(body, value) {
				output <- paramCheck{
					url:   targetURL,
					param: key,
					value: value,
				}
			}
		}
	}
}

func testCanary(ctx context.Context, client *http.Client, check paramCheck) bool {
	canary := "xss" + generateCanary() + "test"
	
	u, err := url.Parse(check.url)
	if err != nil {
		return false
	}

	// Append canary to parameter value
	qs := u.Query()
	qs.Set(check.param, check.value+canary)
	u.RawQuery = qs.Encode()

	body, err := fetchURL(ctx, client, u.String())
	if err != nil {
		return false
	}

	// Check if canary is reflected
	return strings.Contains(body, canary)
}

func testXSSCharacters(ctx context.Context, client *http.Client, check paramCheck, results chan<- result) {
	// XSS test payloads with different contexts
	tests := []struct {
		char    string
		prefix  string
		suffix  string
		context string
	}{
		{`"`, "test", "test", "attribute"},
		{`'`, "test", "test", "attribute"},
		{`<`, "test", "test", "HTML"},
		{`>`, "test", "test", "HTML"},
		{`<script>`, "", "</script>", "script tag"},
		{`javascript:`, "", "", "javascript protocol"},
		{`onclick=`, "", "", "event handler"},
		{`onerror=`, "", "", "event handler"},
	}

	// Additional DOM-based patterns if enabled
	if config.checkDOM {
		tests = append(tests, []struct {
			char    string
			prefix  string
			suffix  string
			context string
		}{
			{`</script><script>`, "", "</script>", "script breakout"},
			{`';alert(1)//`, "", "", "JS string breakout"},
			{`";alert(1)//`, "", "", "JS string breakout"},
			{"`", "test", "test", "template literal"},
		}...)
	}

	// Additional JS context tests if enabled
	if config.checkJS {
		tests = append(tests, []struct {
			char    string
			prefix  string
			suffix  string
			context string
		}{
			{`\`, "test", "test", "escape character"},
			{`${`, "test", "}", "template injection"},
			{`<!--`, "", "-->", "HTML comment"},
			{`/*`, "", "*/", "JS comment"},
		}...)
	}

	for _, test := range tests {
		payload := test.prefix + test.char + test.suffix
		
		u, err := url.Parse(check.url)
		if err != nil {
			continue
		}

		// Test payload
		qs := u.Query()
		qs.Set(check.param, check.value+payload)
		u.RawQuery = qs.Encode()

		body, err := fetchURL(ctx, client, u.String())
		if err != nil {
			continue
		}

		// Check if the dangerous character/payload is reflected without encoding
		if containsUnencoded(body, test.char) {
			results <- result{
				url:       check.url,
				param:     check.param,
				character: test.char,
				context:   test.context,
			}
		}
	}
}

func fetchURL(ctx context.Context, client *http.Client, targetURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", config.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Skip non-HTML responses
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "html") {
		return "", fmt.Errorf("non-HTML content type: %s", contentType)
	}

	// Limit response size
	limited := io.LimitReader(resp.Body, config.maxSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func containsUnencoded(body, char string) bool {
	// Check if character appears unencoded
	if !strings.Contains(body, char) {
		return false
	}

	// Make sure it's not HTML encoded
	encoded := map[string][]string{
		`"`:          {`&quot;`, `&#34;`, `&#x22;`},
		`'`:          {`&#39;`, `&#x27;`, `&apos;`},
		`<`:          {`&lt;`, `&#60;`, `&#x3C;`},
		`>`:          {`&gt;`, `&#62;`, `&#x3E;`},
		`&`:          {`&amp;`, `&#38;`, `&#x26;`},
		`javascript:`: {`javascript&colon;`, `javascript&#58;`},
	}

	// If we find the encoded version, the unencoded one might be intentional
	for _, enc := range encoded[char] {
		if strings.Contains(body, enc) {
			// Found encoded version, but also found unencoded - suspicious
			return true
		}
	}

	// Found unencoded and no encoded version
	return true
}

func generateCanary() string {
	// Simple unique identifier
	return fmt.Sprintf("%d", time.Now().UnixNano())
}