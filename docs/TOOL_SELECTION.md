# Black Cyber Hex — Tool Selection Guide

The framework is an **orchestrator**, not a replacement for mature scanners. The rule is simple: use the strongest focused engine for each job and use Python for scope control, execution, parsing, deduplication, and reporting.

## Port and service scanning — Nmap

Use Nmap when correctness, service/version fingerprints, or NSE checks matter. Black Cyber Hex uses it as the final network-level source of truth.

```bash
nmap -Pn -sV --version-light --top-ports 1000 example.com
nmap -Pn -sV -p- example.com
```

For vulnerability checks, the default uses **safe NSE vulnerability scripts plus Vulners**:

```bash
nmap -Pn -sV --script 'vulners,(vuln and safe)' \
  -p 80,443,8080,8443 example.com
```

For a specifically authorized environment where intrusive NSE behavior is acceptable:

```bash
nmap -Pn -sV --script vuln example.com
```

Why not force Nmap to do everything? Nmap is excellent at services and NSE, but it is not a modern JavaScript crawler and it is not a specialist SQL injection engine.

## Fast port discovery — Masscan

Masscan is an optional **discovery accelerator**. It is not treated as a replacement for Nmap service detection.

```bash
masscan 192.0.2.10 -p80,443,8080 --rate 1000 --wait 2 --open -oJ masscan.json
```

Black Cyber Hex rate-limits Masscan by profile and then relies on Nmap for deeper validation.

## DNS resolution — MassDNS

MassDNS is used for high-volume DNS resolution. It is a resolver, so useful input names still need to come from a candidate list or another discovery source.

```bash
massdns -r resolvers.txt -t A -o Je -w results.jsonl names.txt
```

For accuracy, prefer resolvers you trust. Public resolver lists can be stale or poisoned.

## Live web probing / technology fingerprinting — ProjectDiscovery HTTPX

Once DNS names exist, ProjectDiscovery HTTPX quickly answers: "which names are actually web services?" It also supplies status, title, server, and technology metadata and automatically falls back between HTTPS and HTTP.

```bash
httpx -l hosts.txt -silent -j -sc -title -td -server -fhr -rl 40 -o httpx.jsonl
```

This prevents the crawler and vulnerability scanners from wasting time on dead names. Black Cyber Hex installs this binary as `pd-httpx` to avoid a name collision with the unrelated Python HTTPX CLI; upstream examples still use `httpx`.

## Crawling — Katana

Katana is the endpoint discovery engine because it is designed for automation, JSONL output, scope controls, JavaScript parsing, and rate limiting.

```bash
katana -list live_urls.txt -d 3 -fs fqdn -jc \
  -kf robotstxt,sitemapxml -rl 30 -j -silent -o katana.jsonl
```

Black Cyber Hex keeps crawling scoped to each input FQDN.

## Broad vulnerability checks — Nuclei

Nuclei is used for current template-based web/CVE/misconfiguration coverage. The framework runs it on **live web roots**, not every crawler URL, to reduce duplicate traffic.

```bash
nuclei -l live_urls.txt -silent -j -ni \
  -severity info,low,medium,high,critical -rl 75 -c 20 -o nuclei.jsonl
```

`-ni` disables Interactsh/OAST templates by default so scans do not disclose target data to third-party interaction services. Enable OAST deliberately in a controlled engagement if required.

Update templates with:

```bash
nuclei -ut
```

## Web server checks — Nikto

Nikto adds a different database and test philosophy for server misconfiguration, known files, disclosure, and web-server-specific checks.

```bash
nikto -h https://example.com -nointeractive -Format json -output nikto.json
```

Current Nikto versions are updated from their Git checkout with `git pull`, not the historical `nikto -update` workflow.

## SQL injection — sqlmap

sqlmap is the specialist SQL injection engine. Black Cyber Hex intentionally keeps automated runs at `--risk=1` and passes a bounded set of in-scope parameterized URLs discovered by Katana.

```bash
sqlmap -u 'https://example.com/item?id=1' --batch --level 2 --risk 1 --threads 4
```

Higher sqlmap risk levels can introduce heavier or potentially state-changing tests, so they are not the framework default.

## Why reconFTW and Ghost Eye are not bundled

reconFTW is a useful reference for phase-based recon orchestration, but its full toolchain is intentionally broad and large. Black Cyber Hex takes the orchestration idea while using a much smaller focused set for web scanning. Ghost Eye overlaps substantially with the DNS/network/information-gathering phases already covered here, so vendoring it would add maintenance and dependencies without improving the main scan path.
