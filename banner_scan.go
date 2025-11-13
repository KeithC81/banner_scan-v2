// banner_scan.go
// Banner grabber with safer defaults, custom headers (-H), cookie injection (--set-cookie),
// multi-session cookie-file support (--cookie-file with blank-line separated blocks),
// session-per-target rotation (--session-per-target), and direct -url/-u CLI targets.
// Use responsibly within bounty scope.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	InputURL      string
	FinalURL      string
	RedirectChain string
	Host          string
	IP            string
	Status        int
	Title         string
	Server        string
	ContentType   string
	ContentLen    int64
	LatencyMs     int64
	TLSVersion    string
	TLSIssuer     string
	Err           string
}

var (
	inputFile        = flag.String("input", "targets.txt", "file with list of URLs or paths (one per line). Use empty string to skip file.")
	outputFile       = flag.String("output", "banner_results.csv", "CSV output path")
	perRoot          = flag.Int("perroot", 1, "max concurrent requests per root (domain)")
	concurrency      = flag.Int("concurrency", 25, "global concurrency")
	timeout          = flag.Duration("timeout", 15*time.Second, "per-request timeout")
	limitBytes       = flag.Int64("limit", 128*1024, "max bytes to read when extracting title (bytes)")
	cookieFilePath   = flag.String("cookie-file", "", "path to cookie-file; blocks separated by blank line create multiple sessions")
	sessionPerTarget = flag.Bool("session-per-target", false, "rotate sessions per target (round-robin). Requires cookie-file or set-cookie entries.")
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

var (
	setCookies stringSlice
	headers    stringSlice
	urls       stringSlice
)

func main() {
	// flags
	flag.Var(&setCookies, "set-cookie", "inject cookie(s) into the scanner's cookie jar. Format: NAME=VALUE@domain[/path]. Can be repeated.")
	flag.Var(&headers, "H", "custom request header (repeatable). Format: 'Name: value' or 'Name=Value'")
	flag.Var(&headers, "header", "same as -H")
	flag.Var(&urls, "url", "single URL to scan (repeatable). Example: -url \"https://example.com\"")
	flag.Var(&urls, "u", "shorthand for -url")
	flag.Parse()

	// Read file targets (if inputFile non-empty)
	ins := []string{}
	if *inputFile != "" {
		fileLines, err := readLines(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading input file: %v\n", err)
			os.Exit(1)
		}
		ins = append(ins, fileLines...)
	}

	// Append CLI -url entries, dedupe preserving order
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		found := false
		for _, e := range ins {
			if e == u {
				found = true
				break
			}
		}
		if !found {
			ins = append(ins, u)
		}
	}

	if len(ins) == 0 {
		fmt.Fprintf(os.Stderr, "no targets provided: use -input <file> or -url <url>\n")
		os.Exit(1)
	}

	// Build session specs
	var sessionSpecs [][]string
	var err error
	if *cookieFilePath != "" {
		sessionSpecs, err = parseCookieFileBlocks(*cookieFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing cookie-file: %v\n", err)
			os.Exit(1)
		}
	}
	if len(setCookies) > 0 && len(sessionSpecs) == 0 {
		// If no cookie-file, treat --set-cookie entries as one session
		sessionSpecs = [][]string{setCookies}
	}

	// Redirect-chain capture store (shared across clients)
	var redirectMap sync.Map

	// Build client(s)
	var clients []*http.Client
	if len(sessionSpecs) > 0 {
		for _, specs := range sessionSpecs {
			jar, _ := cookiejar.New(nil)
			if len(specs) > 0 {
				if err := applySetCookies(jar, specs); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to apply some set-cookie entries: %v\n", err)
				}
			}
			cl := makeClientWithJar(jar)
			configureRedirectCapture(cl, &redirectMap)
			clients = append(clients, cl)
		}
	} else {
		jar, _ := cookiejar.New(nil)
		cl := makeClientWithJar(jar)
		configureRedirectCapture(cl, &redirectMap)
		clients = []*http.Client{cl}
	}

	// Warn if rotation requested but only one session
	if *sessionPerTarget && len(clients) <= 1 {
		fmt.Fprintf(os.Stderr, "warning: --session-per-target requested but only %d session(s) available; continuing with single client\n", len(clients))
	}

	// Prepare CSV
	outf, err := os.Create(*outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output: %v\n", err)
		os.Exit(1)
	}
	defer outf.Close()
	w := csv.NewWriter(outf)
	defer w.Flush()
	w.Write([]string{
		"input_url", "final_url", "redirect_chain", "host", "ip", "status",
		"title", "server", "content_type", "content_length", "latency_ms", "tls_version", "tls_issuer", "error",
	})

	// per-root semaphores (domain throttling)
	rootSem := &sync.Map{} // map[string]chan struct{}
	getSem := func(root string) chan struct{} {
		v, _ := rootSem.LoadOrStore(root, make(chan struct{}, *perRoot))
		return v.(chan struct{})
	}

	// Round-robin counter for session-per-target
	var rr uint64
	clientCount := uint64(len(clients))

	// Worker pool
	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range jobs {
				// Pick client
				var client *http.Client
				if *sessionPerTarget && clientCount > 0 {
					idx := atomic.AddUint64(&rr, 1)
					client = clients[(idx-1)%clientCount]
				} else {
					client = clients[0]
				}
				res := fetchOneWithClient(raw, client, getSem, &redirectMap, headers)
				recordResult(w, res)
			}
		}()
	}

	for _, line := range ins {
		if strings.TrimSpace(line) == "" {
			continue
		}
		jobs <- line
	}
	close(jobs)
	wg.Wait()

	fmt.Fprintf(os.Stderr, "done. sessions=%d clients=%d\n", len(sessionSpecs), len(clients))
}

func makeClientWithJar(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   6 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     30 * time.Second,
			MaxIdleConnsPerHost: 20,
			// Don't force Accept-Encoding; let Go add gzip and auto-decompress it.
		},
		Jar:     jar,
		Timeout: *timeout + 5*time.Second,
	}
}

func configureRedirectCapture(client *http.Client, redirectMap *sync.Map) {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if v := req.Context().Value("scanID"); v != nil {
			key := v.(string)
			chain := make([]string, 0, len(via)+1)
			for _, r := range via {
				chain = append(chain, r.URL.String())
			}
			chain = append(chain, req.URL.String())
			redirectMap.Store(key, strings.Join(chain, " -> "))
		}
		if len(via) > 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// parse cookie-file blocks: blank line separates sessions; each line is NAME=VALUE@domain[/path]
func parseCookieFileBlocks(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var blocks [][]string
	var cur []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = nil
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

// Apply --set-cookie specs into jar. Format: NAME=VALUE@domain[/path]
func applySetCookies(jar http.CookieJar, specs []string) error {
	for _, s := range specs {
		parts := strings.SplitN(s, "@", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid cookie spec (missing @): %q", s)
		}
		left, right := parts[0], parts[1]
		kv := strings.SplitN(left, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid name=value in: %q", left)
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		domain := right
		pathVal := "/"
		if strings.Contains(right, "/") {
			idx := strings.Index(right, "/")
			domain = right[:idx]
			pathVal = right[idx:]
			if pathVal == "" {
				pathVal = "/"
			}
		}
		u, err := url.Parse("https://" + domain)
		if err != nil {
			return fmt.Errorf("invalid domain in cookie spec %q: %v", s, err)
		}
		u.Path = pathVal
		c := &http.Cookie{
			Name:     name,
			Value:    value,
			Domain:   domain,
			Path:     pathVal,
			Secure:   true,
			HttpOnly: true,
		}
		jar.SetCookies(u, []*http.Cookie{c})
	}
	return nil
}

// readLines reads a file into lines (skipping empty/comment lines)
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func recordResult(w *csv.Writer, r *Result) {
	if r == nil {
		return
	}
	row := []string{
		r.InputURL,
		r.FinalURL,
		r.RedirectChain,
		r.Host,
		r.IP,
		strconv.Itoa(r.Status),
		r.Title,
		r.Server,
		r.ContentType,
		strconv.FormatInt(r.ContentLen, 10),
		strconv.FormatInt(r.LatencyMs, 10),
		r.TLSVersion,
		r.TLSIssuer,
		r.Err,
	}
	w.Write(row)
	w.Flush()
}

// fetchOneWithClient: HEAD then GET (limited), applies custom headers to both, captures metadata.
func fetchOneWithClient(raw string, client *http.Client, semGetter func(string) chan struct{}, redirectMap *sync.Map, hdrs []string) *Result {
	res := &Result{InputURL: raw, FinalURL: raw}

	u := normalizeURL(raw)
	res.Host = u.Hostname()

	// resolve IP (best-effort)
	if ips, err := net.LookupIP(u.Hostname()); err == nil && len(ips) > 0 {
		res.IP = ips[0].String()
	}

	// per-root semaphore (domain)
	root := u.Hostname()
	sem := semGetter(root)
	sem <- struct{}{}         // acquire
	defer func() { <-sem }()  // release

	// context with scan ID for redirect tracking
	scanID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixNano()%1000)
	ctx := context.WithValue(context.Background(), "scanID", scanID)

	// HEAD request
	headReq, _ := http.NewRequestWithContext(ctx, "HEAD", u.String(), nil)
	// defaults
	headReq.Header.Set("User-Agent", "banner-scan/1.0")
	headReq.Header.Set("Accept", "*/*")
	headReq.Header.Set("Connection", "keep-alive")
	// user headers override defaults
	applyCustomHeaders(headReq, hdrs)

	t0 := time.Now()
	headResp, headErr := client.Do(headReq)
	res.LatencyMs = time.Since(t0).Milliseconds()
	if headErr != nil {
		res.Err = headErr.Error()
		return res
	}
	defer headResp.Body.Close()

	res.Status = headResp.StatusCode
	res.FinalURL = headResp.Request.URL.String()
	res.Server = headResp.Header.Get("Server")
	res.ContentType = headResp.Header.Get("Content-Type")
	if cl := headResp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			res.ContentLen = n
		}
	}

	// capture redirect chain if any
	if v, ok := redirectMap.Load(scanID); ok {
		res.RedirectChain = v.(string)
	}

	// handle 429 Retry-After politely
	if headResp.StatusCode == 429 {
		if ra := headResp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil {
				time.Sleep(time.Duration(secs) * time.Second)
			} else if t, err := http.ParseTime(ra); err == nil {
				time.Sleep(time.Until(t))
			}
		}
		return res
	}

	// If content-type suggests it's worth fetching a bit of body, GET with limit
	if headResp.StatusCode >= 200 && headResp.StatusCode < 400 {
		ct := strings.ToLower(res.ContentType)
		if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml") ||
			strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain") || ct == "" {
			getReq, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			getReq.Header.Set("User-Agent", "banner-scan/1.0")
			getReq.Header.Set("Accept", "*/*")
			getReq.Header.Set("Connection", "keep-alive")
			applyCustomHeaders(getReq, hdrs)

			t1 := time.Now()
			getResp, getErr := client.Do(getReq)
			res.LatencyMs = time.Since(t1).Milliseconds()
			if getErr != nil {
				res.Err = getErr.Error()
				return res
			}
			defer getResp.Body.Close()

			res.Status = getResp.StatusCode
			res.FinalURL = getResp.Request.URL.String()
			if v, ok := redirectMap.Load(scanID); ok {
				res.RedirectChain = v.(string)
			}
			res.Server = firstNonEmpty(res.Server, getResp.Header.Get("Server"))
			res.ContentType = firstNonEmpty(res.ContentType, getResp.Header.Get("Content-Type"))
			if cl := getResp.Header.Get("Content-Length"); cl != "" {
				if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
					res.ContentLen = n
				}
			}
			// TLS info
			if getResp.TLS != nil {
				res.TLSVersion = tlsVersion(getResp.TLS.Version)
				if len(getResp.TLS.PeerCertificates) > 0 {
					res.TLSIssuer = getResp.TLS.PeerCertificates[0].Issuer.CommonName
				}
			}
			// 429 handling on GET
			if getResp.StatusCode == 429 {
				if ra := getResp.Header.Get("Retry-After"); ra != "" {
					if secs, err := strconv.Atoi(ra); err == nil {
						time.Sleep(time.Duration(secs) * time.Second)
					} else if t, err := http.ParseTime(ra); err == nil {
						time.Sleep(time.Until(t))
					}
				}
				return res
			}

			// Read limited bytes and extract title (regex)
			lim := io.LimitReader(getResp.Body, *limitBytes)
			banner, _ := io.ReadAll(lim)
			res.Title = extractTitleFromBytes(banner)
		}
	}

	return res
}

func normalizeURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return u
	}
	u2, _ := url.Parse("https://" + strings.TrimSpace(raw))
	return u2
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%x)", v)
	}
}

// Simple <title> extractor via regex on limited bytes.
var titleRe = regexp.MustCompile(`(?is)<\s*title[^>]*>(.*?)<\s*/\s*title\s*>`)

func extractTitleFromBytes(b []byte) string {
	m := titleRe.FindSubmatch(b)
	if len(m) >= 2 {
		txt := strings.TrimSpace(string(m[1]))
		return html.UnescapeString(txt)
	}
	return ""
}

// ---------- Custom header handling ----------

func parseHeaderSpec(s string) (name, value string, ok bool) {
	// Accept "Name: value" or "Name=Value"
	if i := strings.Index(s, ":"); i != -1 {
		name = strings.TrimSpace(s[:i])
		value = strings.TrimSpace(s[i+1:])
	} else if i := strings.Index(s, "="); i != -1 {
		name = strings.TrimSpace(s[:i])
		value = strings.TrimSpace(s[i+1:])
	} else {
		return "", "", false
	}
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

func applyCustomHeaders(req *http.Request, hdrs []string) {
	for _, h := range hdrs {
		name, value, ok := parseHeaderSpec(h)
		if !ok {
			continue
		}
		// Handle Host specially
		if strings.EqualFold(name, "Host") {
			req.Host = value
			continue
		}
		// Avoid requesting brotli we can't decode
		if strings.EqualFold(name, "Accept-Encoding") && strings.Contains(strings.ToLower(value), "br") {
			value = strings.ReplaceAll(value, "br", "")
			value = strings.ReplaceAll(value, ", ,", ",")
			value = strings.Trim(value, ", ")
		}
		req.Header.Set(name, value)
	}
}
