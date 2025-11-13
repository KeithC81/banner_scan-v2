## Quick orientation

This repo is a single-file Go CLI tool: `banner_scan.go`. Build and run from the project root.

- Build: `go build -o banner_scan banner_scan.go` (matches README)
- Module: `go.mod` references `golang.org/x/net` and requires Go 1.24.x

The main responsibilities:
- Read targets (file `-input` or `-url` flags)
- Perform HEAD/GET requests with custom headers and cookie sessions
- Respect per-root throttling (`-perroot`) and global concurrency (`-concurrency`)
- Emit a CSV with fixed columns (see "CSV output" below)

## Key files to inspect
- `banner_scan.go` — the whole program. All behavior is implemented here (flag parsing, HTTP clients, worker pool, CSV writer).
- `README.md` — contains build and run examples you should preserve when changing CLI semantics.
- `go.mod` — dependency list and Go version.

## Important code patterns & conventions (do not break)
- Flags: the CLI uses `flag.Var` with a custom `stringSlice` type for repeatable options (`-url`, `-H`, `--set-cookie`). When adding repeatable flags, follow the same pattern.
- Cookie handling: `--set-cookie` entries are parsed as `NAME=VALUE@domain[/path]`. A `--cookie-file` is parsed into blocks separated by blank lines; each block becomes a session (cookie jar). Lines starting with `#` or `//` are ignored. See `parseCookieFileBlocks` and `applySetCookies` in `banner_scan.go`.
- Session rotation: `--session-per-target` uses a round-robin counter (atomic) across created clients. If you change how clients are constructed, keep rotation semantics consistent.
- Redirect capture: the program stores redirect chains in a `sync.Map` via `client.CheckRedirect` and uses a `scanID` context value. If you modify redirect behavior, preserve the `scanID` key usage or update both the redirect capture and where it's read.
- Throttling: domain-level throttling is implemented as `map[string]chan struct{}` semaphores (stored in `sync.Map`) sized by `-perroot`. Preserve this approach if you refactor concurrency.
- Header format: accepts `Name: value` or `Name=Value`. `Host:` is applied to `req.Host` to override virtual host. The code strips `br` from `Accept-Encoding` to avoid brotli decoding issues.

## CSV output (columns)
The program writes a CSV header in this exact order — keep it stable unless you update the README and consumers:

input_url, final_url, redirect_chain, host, ip, status, title, server, content_type, content_length, latency_ms, tls_version, tls_issuer, error

If you change column order or names, update `recordResult` in `banner_scan.go` and README examples that parse the CSV.

## Build / run / debug workflows
- Build: `go build -o banner_scan banner_scan.go`
- Quick run (single URL): `./banner_scan -input "" -url "https://example.com" -output out.csv -H "X-Program-Auth: token"`
- Scan file: `./banner_scan -input targets.txt -output out.csv`
- Cookie-file format: blank-line separated blocks; `--session-per-target` rotates these sessions across targets.

Debug tips
- To debug redirects or request lifecycle, add logging around `configureRedirectCapture`, and ensure the `scanID` value is propagated to request contexts.
- The client creation helper is `makeClientWithJar` — network params (timeouts, keepalive, MaxIdleConnsPerHost) are set there.

## Tests and CI
- There are no unit tests in the repo. Keep code changes small and verify by building and running the binary against a file of test targets.
- Minimal verification to run locally:
  - `go build` must succeed
  - Run a short scan: `./banner_scan -input sample_targets.txt -concurrency 2 -perroot 1 -output test_out.csv`

## Examples to copy into PR descriptions
- If you change CLI flags or cookie semantics, include a small example using `--set-cookie` and `--cookie-file` format, plus expected CSV header. This repo's README contains reference examples — keep them in sync.

## When editing this file
- If you add new flags, document them in `README.md` and ensure examples still work.
- If you change concurrency, semaphores, or client behavior, run the quick verification above and mention the effect in PR description.

If anything below is unclear or you want more details (for example: where title extraction occurs or how TLS issuer is extracted), tell me which part to expand and I'll update this document.
