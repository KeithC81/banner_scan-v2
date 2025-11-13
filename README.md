READ.ME





~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#  Build from source (file: banner_scan.go)

go build -o banner_scan banner_scan.go
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~






~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Basic usage
# scan targets from a file (default behaviour)

./banner_scan -input targets.txt -output out.csv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


   



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#  Flags (full list)

-input string             file with list of URLs or paths (one per line). Use empty string to skip file. (default "targets.txt")
-output string            CSV output path (default "banner_results.csv")
-url, -u string          single URL to scan (repeatable). Example: -url "https://example.com"
-set-cookie string       inject cookie(s) into the scanner's cookie jar. Format: NAME=VALUE@domain[/path]. Repeatable.
-cookie-file string      path to cookie-file; blank-line separated blocks create multiple sessions
-session-per-target      rotate sessions per target (round-robin). Requires cookie-file or set-cookie entries.
-H, -header string       custom request header (repeatable). Format: "Name: value" or "Name=Value"
-perroot int             max concurrent requests per root (domain). Default: 1
-concurrency int         global concurrency (worker pool size). Default: 25
-timeout duration        per-request timeout (e.g., 10s, 2m). Default: 15s
-limit int               max bytes to read when extracting title (bytes). Default: 131072 (128 KiB)
Cookie formats
--set-cookie (single quick cookie)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~







~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Format:
# NAME=VALUE@domain[/path]

# Examples:


--set-cookie "sessionid=ABC123@example.com/"
--set-cookie "auth=eyJ...@accounts.example.com/account"
--cookie-file (multiple sessions)
##Each non-empty line is a NAME=VALUE@domain[/path].

##Blank line separates sessions (one client/jar per block).


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


  cookie-file example (sessions.txt):



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# session 1
sessionid=ABC123@example.com/
auth=xyz@example.com/account

# session 2
sessionid=DEF456@example.com/
#Use with --session-per-target to rotate sessions per target (round-robin).

#Header formats (-H / --header)
#Accepts Name: value or Name=Value. Repeatable.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Examples:



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-H "X-Program-Auth: Kth-hello"
-H "Origin: https://example.com"
-H "Host: beta.example.com"     # sets virtual Host header (req.Host)
-H "Accept-Encoding: gzip, deflate"  # note: br is stripped automatically to avoid brotli decode issues
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Notes:

    Host: is applied via req.Host (correct virtual host override).

    If you include Accept-Encoding: ... br the scanner strips br to avoid undecoded responses.

Common workflows / examples:

1) One-off quick URL



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -url "https://example.com" -output out.csv -H "X-Program-Auth: Kth-hello"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


2) Scan a file of targets



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -input targets.txt -output out.csv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


3) Use a single session cookie (quick authenticated scan)



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -input targets.txt \
  --set-cookie "sessionid=ABC123@example.com/" \
  -H "X-Program-Auth: Kth-hello" \
  -output out.csv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


4) Multiple sessions (cookie-file) + rotate per target (multi-user testing)



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -input targets.txt \
  --cookie-file sessions.txt \
  --session-per-target \
  -perroot 1 -concurrency 40 \
  -output out.csv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


5) Fast low-noise HEAD-first sweep (tweak limits)



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -input shortlist.txt -output out.csv -perroot 1 -concurrency 80 -timeout 8s -limit 65536
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


6) One-off header-heavy request (SNI/Host tests)



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
./banner_scan -url "https://target.example" -H "Host: host.variant.example" -H "X-My: val"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CSV output columns (what the results file contains)

    input_url, final_url, redirect_chain, host, ip, status, title, server, content_type, content_length, latency_ms, tls_version, tls_issuer, error

    redirect_chain shows redirect hops captured (useful for WAF/cdn observation).

    content_length is the server Content-Length header (may be 0 or empty for chunked transfers).

    latency_ms is measured per HEAD/GET call (helps spot timeouts/slow endpoints).

    tls_issuer and tls_version help fingerprint CDN/origin.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    
    
   

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# How to use -url (examples)

# for single url escape with -input ""


# File + CLI:
./banner_scan -input testv2-urls.txt -url "https://one-off.example.com" -output out.csv 

./banner_scan -input "" -url "https://target.example" -H "Host: host.variant.example" -H "X-My: Hello" -output out2.csv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    
    
    
   
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #dig +short target.example


#nslookup target.example

#Quick curl test using --resolve (override DNS, useful for testing SNI/Host combos)
# pretend 1.2.3.4 is the IP you want to hit

curl -I -s -k --resolve "target.example:443:1.2.3.4" \
  -H "Host: host.variant.example" -H "X-My: Hello" "https://target.example"

#Add a temporary /etc/hosts mapping (local test)

sudo -- sh -c 'echo "1.2.3.4 target.example host.variant.example" >> /etc/hosts'

# then run your banner_scan (or curl) normally
# remove it afterwards (edit file or use sed to remove line)

#Show only rows with errors from your CSV (quick filter)

# assuming error is the last field

awk -F, 'NR==1 || $NF!="" { print }' out2.csv

#Re-run the scanner forcing no file input (what you did — good)

./banner_scan -input "" -url "https://target.example" -H "Host: host.variant.example" -H "X-My: Hello" -output out2.csv

    
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    
    

