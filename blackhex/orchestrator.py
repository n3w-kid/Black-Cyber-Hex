from __future__ import annotations
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from .builtin import baseline_http
from .config import Profile
from .findings import Finding, deduplicate
from .parsers import parse_httpx, parse_katana, parse_masscan, parse_massdns, parse_nikto, parse_nmap, parse_nuclei, parse_sqlmap
from .report import write_report
from .scope import Scope, host_from_target, url_from_target
from .tools import nmap_scan, masscan_scan, massdns_scan, httpx_probe, katana_scan, nuclei_scan, nikto_scan, sqlmap_scan


def make_run_dir(base: Path, target: str) -> Path:
    host = host_from_target(target).replace(":", "_")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    d = base / f"{host}-{stamp}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _parameterized_urls(urls: list[str], scope: Scope, max_urls: int) -> list[str]:
    keep = []
    for u in urls:
        try:
            p = urlparse(u)
            if scope.allows_url(u) and p.query and "=" in p.query:
                keep.append(u)
        except Exception:
            pass
    return sorted(set(keep))[:max_urls]


def full_scan(target: str, base_out: Path, profile: Profile, include_masscan: bool = False, include_dns: bool = True, intrusive_nse: bool = False) -> tuple[Path, list[Finding]]:
    out = make_run_dir(base_out, target)
    scope = Scope(target)
    findings: list[Finding] = []
    runs: list[dict] = []

    # Zero-dependency baseline first: fast feedback even if external tools are missing.
    findings.extend(baseline_http(url_from_target(target)))

    if include_masscan:
        run, path = masscan_scan(target, out, profile)
        runs.append(run.to_dict())
        findings.extend(parse_masscan(path))

    run, path = nmap_scan(target, out, profile, vuln=False)
    runs.append(run.to_dict())
    findings.extend(parse_nmap(path))

    resolved_names: list[str] = []
    # DNS enrichment is for hostname/URL targets; CIDRs stay in the network-scanner path.
    is_cidr = "/" in target and "://" not in target
    if include_dns and not is_cidr:
        run, path = massdns_scan(target, out)
        runs.append(run.to_dict())
        dns_findings = parse_massdns(path)
        findings.extend(dns_findings)
        resolved_names = [f.target for f in dns_findings if f.target and scope.allows_host(f.target)]

    probe_inputs = out / "httpx_inputs.txt"
    seed = [url_from_target(target)] + resolved_names
    probe_inputs.write_text("\n".join(dict.fromkeys(seed)) + "\n", encoding="utf-8")
    run, path = httpx_probe(target, out, profile, probe_inputs)
    runs.append(run.to_dict())
    httpx_findings, live_urls = parse_httpx(path)
    live_urls = [u for u in live_urls if scope.allows_url(u)]
    findings.extend([f for f in httpx_findings if scope.allows_url(f.target)])
    if not live_urls:
        live_urls = [url_from_target(target)]

    live_file = out / "live_urls.txt"
    live_file.write_text("\n".join(live_urls) + "\n", encoding="utf-8")

    run, path = katana_scan(target, out, profile, live_file)
    runs.append(run.to_dict())
    katana_findings, urls = parse_katana(path)
    urls = [u for u in urls if scope.allows_url(u)]
    findings.extend([f for f in katana_findings if scope.allows_url(f.target)])

    urls_file = out / "urls.txt"
    urls_file.write_text("\n".join(urls or live_urls) + "\n", encoding="utf-8")

    # Nuclei runs on live web roots rather than every crawled path to avoid duplicate traffic.
    run, path = nuclei_scan(target, out, profile, live_file)
    runs.append(run.to_dict())
    findings.extend(parse_nuclei(path))

    run, path = nikto_scan(target, out)
    runs.append(run.to_dict())
    findings.extend(parse_nikto(path))

    run, path = nmap_scan(target, out, profile, vuln=True, intrusive=intrusive_nse)
    runs.append(run.to_dict())
    findings.extend(parse_nmap(path))

    sql_urls = _parameterized_urls(urls, scope, profile.max_sqlmap_urls)
    sql_file = out / "sqlmap_urls.txt"
    if sql_urls:
        sql_file.write_text("\n".join(sql_urls) + "\n", encoding="utf-8")
        run = sqlmap_scan(target, out, profile, sql_file)
        runs.append(run.to_dict())
        findings.extend(parse_sqlmap(Path(run.stdout_file), target))
    else:
        sql_file.write_text("# No in-scope parameterized URLs discovered by Katana.\n", encoding="utf-8")

    normalized = deduplicate(findings)
    write_report(out, target, normalized, runs)
    return out, normalized
