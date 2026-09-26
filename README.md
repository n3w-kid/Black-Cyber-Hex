# Black Cyber Hex

**Black Cyber Hex** is a Python-first, menu-driven web security scanning orchestrator for systems you own or are explicitly authorized to test. It does not reinvent mature scanners: it chooses the best focused tool for each phase, runs them with controlled defaults, normalizes their output, deduplicates findings, and produces one JSON + Markdown report.

## Tool selection

| Purpose | Primary tool | Why it is used |
|---|---|---|
| Port/service discovery + validation | **Nmap** | Accurate service/version detection, XML output, and NSE integration. Nmap is the validation backbone. |
| Fast port discovery | **Masscan** | Optional fast SYN discovery; results are treated as leads and validated with Nmap. |
| DNS bulk resolution | **MassDNS** | Very fast bulk resolver for candidate subdomains / DNS names. |
| Live web / technology probe | **ProjectDiscovery HTTPX** (`pd-httpx` inside Black Cyber Hex) | Quickly turns resolved names into live HTTP(S) roots, with status/title/server/technology metadata. |
| Crawling/endpoints | **Katana** | Modern crawler with JSONL output, scope controls, JS parsing, and rate limiting. |
| Broad web/CVE checks | **Nuclei** | Current community template ecosystem with structured JSONL and severity metadata. |
| Web server misconfiguration | **Nikto** | Mature web-server-focused checks and a distinct test database. |
| SQL injection detection | **sqlmap** | Specialist SQLi detector. Black Cyber Hex keeps `--risk=1` by default and feeds it only a bounded set of in-scope parameterized URLs found by Katana. |
| Baseline HTTP security | Built-in Python | Zero-dependency header baseline so you still get immediate output if external scanners are missing. |

The framework borrows the **phase-based orchestration** idea from reconFTW but does not bundle reconFTW itself because its documented installation footprint is much larger than a focused container. Ghost Eye is also not vendored; its information-gathering jobs are covered by the tools above without duplicating another Python dependency tree.

## Start quickly with Docker

```bash
docker compose build
docker compose run --rm black-cyber-hex
# or: make docker-run
```
```
installing 
cd black-cyber-hex

# Docker
docker compose build
docker compose run --rm black-cyber-hex

# Or native Linux
./install.sh
./blackhex.sh doctor
./blackhex.sh
```
For raw Nmap/Masscan scans, the compose file grants `NET_RAW`/`NET_ADMIN` and uses host networking on Linux. If you do not need Masscan or SYN scanning, the framework can also run without those capabilities; Nmap falls back to TCP connect scanning when not root.

The first Nuclei run may download templates. To refresh scanner data later, select **Update scanner databases/templates** or run:

```bash
docker compose run --rm black-cyber-hex update
```

## Native Linux install

```bash
./install.sh
./blackhex.sh doctor
./blackhex.sh
```

The Python orchestration layer has **no PyPI dependencies**. The ProjectDiscovery HTTPX binary is installed as `pd-httpx` internally to avoid colliding with the unrelated Python `httpx` command.

## Non-interactive examples

```bash
# Combined scan. Authorization must be explicit in non-interactive mode.
python3 bch.py scan https://example.com --authorized

# Faster profile and optional Masscan discovery.
python3 bch.py --profile fast scan https://example.com --masscan --authorized

# Nmap service scan.
python3 bch.py nmap example.com --authorized

# All TCP ports with Nmap.
python3 bch.py nmap example.com --all-ports --authorized

# Nmap vulnerability scan: safe NSE vuln scripts + Vulners.
python3 bch.py nmap example.com --vuln --authorized

# Full Nmap vuln category (can include intrusive scripts; use only when authorized and appropriate).
python3 bch.py nmap example.com --vuln --intrusive-nse --authorized

# MassDNS with your own candidate names and trusted resolvers.
python3 bch.py dns example.com --candidates names.txt --resolvers resolvers.txt --authorized

# Masscan only, rate controlled by the selected profile.
python3 bch.py masscan 192.0.2.10 --ports 80,443,8080 --authorized

# Specialist scans.
python3 bch.py httpx https://example.com --authorized
python3 bch.py crawl https://example.com --authorized
python3 bch.py nuclei https://example.com --authorized
python3 bch.py nikto https://example.com --authorized
python3 bch.py sqlmap 'https://example.com/item?id=1' --authorized
```

## Nmap vulnerability scanning

Black Cyber Hex deliberately gets maximum useful value from Nmap without pretending Nmap is a web crawler or SQLi specialist.

Safe default:

```bash
nmap -Pn -sV --version-light \
  --script 'vulners,(vuln and safe)' \
  -p 80,443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443 \
  example.com
```

Broader authorized test:

```bash
nmap -Pn -sV --script vuln example.com
```
```
./blackhex.sh nmap example.com \
  --vuln \
  --intrusive-nse \
  --authorized
```

Nmap's `vulners` NSE script uses detected software versions/CPEs and queries the Vulners service. That is a better fit than trying to ship a huge local vulnerability database inside this small image. `nmap --script-updatedb` refreshes the local NSE script index; update the Nmap package itself to receive newer bundled scripts.

## Scan workflow

The combined scan runs this pipeline:

1. Built-in HTTP baseline.
2. Optional Masscan web-port discovery.
3. Nmap service/version scan.
4. MassDNS resolution of the root plus a small built-in candidate list.
5. HTTPX probes the root plus resolved in-scope names and keeps live HTTP(S) services.
6. Katana crawls those live roots, constrained per FQDN, including JS endpoint parsing.
7. Nuclei scans the live roots (not every crawled path, which avoids duplicate traffic).
8. Nikto scans the primary web target.
9. Nmap safe vulnerability scripts + Vulners.
10. sqlmap only scans a bounded list of parameterized URLs discovered by Katana.
11. Normalize and deduplicate into `summary.json` and `summary.md`.

Raw scanner output is always retained beside the normalized report so you can audit why a finding exists.

## Profiles

- **safe**: lower rate, shallower crawl, fewer ports/SQLi targets.
- **balanced**: default accuracy/speed compromise.
- **fast**: higher but still bounded rates for controlled lab or authorized environments.

Nuclei OAST/Interactsh checks are disabled by default (`-ni`) so the target is not disclosed to third-party interaction services. sqlmap stays at `--risk=1`; use a targeted manual engagement if you need more invasive tests.

## Output layout

```text
reports/
└── example.com-YYYYMMDD-HHMMSS/
    ├── summary.md
    ├── summary.json
    ├── nmap.xml
    ├── nmap_vuln.xml
    ├── httpx.jsonl
    ├── katana.jsonl
    ├── nuclei.jsonl
    ├── nikto.json
    ├── massdns.jsonl
    ├── sqlmap.stdout.log
    └── *.command.txt / *.run.json / *.stderr.log
```

## Notes

- MassDNS is a **resolver**, not a magical subdomain source. Supply a good candidate list for deeper enumeration; the default list is intentionally small.
- Masscan is optional because it trades depth for speed. Nmap validates services and versions afterward.
- Do not blindly enable Nmap intrusive/DoS/exploit NSE categories on production systems.
- Keep templates and scanner versions current; signatures go stale quickly.

## Developer checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q .
bash -n install.sh scripts/nmap-vuln.sh
```

For the detailed purpose/command rationale, see [`docs/TOOL_SELECTION.md`](docs/TOOL_SELECTION.md).

