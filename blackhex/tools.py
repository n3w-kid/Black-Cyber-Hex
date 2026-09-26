from __future__ import annotations
import os
import shutil
import socket
from urllib.parse import urlparse
from pathlib import Path
from .config import Profile, WEB_PORTS, COMMON_SUBDOMAINS
from .runner import run_command, CommandResult
from .scope import host_from_target, url_from_target


def _explicit_port(target: str) -> int | None:
    try:
        if "://" in target:
            return urlparse(target).port
        # host:port (avoid treating IPv6 as this shorthand)
        if target.count(":") == 1 and "/" not in target:
            maybe = target.rsplit(":", 1)[1]
            if maybe.isdigit() and 1 <= int(maybe) <= 65535:
                return int(maybe)
    except ValueError:
        return None
    return None


def _merge_ports(ports: str, extra: int | None) -> str:
    if not extra:
        return ports
    parts = [x.strip() for x in ports.split(",") if x.strip()]
    if str(extra) not in parts:
        parts.append(str(extra))
    return ",".join(parts)


def _scan_type() -> str:
    return "-sS" if hasattr(os, "geteuid") and os.geteuid() == 0 else "-sT"


def nmap_scan(target: str, out: Path, profile: Profile, vuln: bool = False, all_ports: bool = False, intrusive: bool = False) -> tuple[CommandResult, Path]:
    xml = out / ("nmap_vuln.xml" if vuln else "nmap.xml")
    cmd = ["nmap", "-Pn", _scan_type(), "-sV", "--version-light", "--open", f"-{profile.nmap_timing}"]
    explicit_port = _explicit_port(target)
    if all_ports:
        cmd += ["-p-"]
    elif explicit_port:
        cmd += ["-p", str(explicit_port)]
    elif vuln:
        cmd += ["-p", WEB_PORTS]
    else:
        cmd += ["--top-ports", str(profile.nmap_top_ports)]
    if vuln:
        script_expr = "vulners,vuln" if intrusive else "vulners,(vuln and safe)"
        cmd += ["--script", script_expr]
    scan_target = host_from_target(target) if "://" in target else target
    cmd += ["-oX", str(xml), scan_target]
    return run_command("nmap_vuln" if vuln else "nmap", cmd, out), xml


def masscan_scan(target: str, out: Path, profile: Profile, ports: str = WEB_PORTS) -> tuple[CommandResult, Path]:
    result_path = out / "masscan.json"
    host = host_from_target(target)
    scan_target = target
    if "://" in target:
        scan_target = host
    try:
        socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            scan_target = socket.gethostbyname(host)
        except OSError:
            scan_target = host
    ports = _merge_ports(ports, _explicit_port(target))
    cmd = ["masscan", scan_target, "-p", ports, "--rate", str(profile.masscan_rate), "--wait", "2", "--open", "-oJ", str(result_path)]
    return run_command("masscan", cmd, out), result_path


def massdns_scan(target: str, out: Path, resolvers: Path | None = None, candidates_file: Path | None = None) -> tuple[CommandResult, Path]:
    domain = host_from_target(target)
    candidates = out / "massdns_candidates.txt"
    if candidates_file and candidates_file.exists():
        candidates.write_text(candidates_file.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    else:
        candidates.write_text("\n".join([domain] + [f"{x}.{domain}" for x in COMMON_SUBDOMAINS]) + "\n", encoding="utf-8")
    resolver_file = resolvers or Path("/etc/resolv.conf")
    if str(resolver_file) == "/etc/resolv.conf":
        generated = out / "resolvers.txt"
        nameservers = []
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                if line.strip().startswith("nameserver "):
                    nameservers.append(line.split()[1])
        except Exception:
            pass
        if not nameservers:
            nameservers = ["1.1.1.1", "8.8.8.8"]
        generated.write_text("\n".join(nameservers) + "\n", encoding="utf-8")
        resolver_file = generated
    output = out / "massdns.jsonl"
    cmd = ["massdns", "-r", str(resolver_file), "-t", "A", "-o", "Je", "-w", str(output), str(candidates)]
    return run_command("massdns", cmd, out), output


def httpx_probe(target: str, out: Path, profile: Profile, host_file: Path | None = None) -> tuple[CommandResult, Path]:
    output = out / "httpx.jsonl"
    cmd = ["pd-httpx", "-silent", "-j", "-sc", "-title", "-td", "-server", "-fhr", "-rl", str(profile.httpx_rate), "-o", str(output)]
    if host_file and host_file.exists() and host_file.stat().st_size:
        cmd += ["-l", str(host_file)]
    else:
        cmd += ["-u", url_from_target(target)]
    return run_command("httpx", cmd, out), output


def katana_scan(target: str, out: Path, profile: Profile, url_file: Path | None = None) -> tuple[CommandResult, Path]:
    output = out / "katana.jsonl"
    cmd = ["katana", "-d", str(profile.katana_depth), "-fs", "fqdn", "-rl", str(profile.katana_rate), "-c", "10", "-jc", "-j", "-silent", "-o", str(output)]
    if profile.katana_depth >= 3:
        cmd += ["-kf", "robotstxt,sitemapxml"]
    if url_file and url_file.exists() and url_file.stat().st_size:
        cmd += ["-list", str(url_file)]
    else:
        cmd += ["-u", url_from_target(target)]
    return run_command("katana", cmd, out), output


def nuclei_scan(target: str, out: Path, profile: Profile, url_file: Path | None = None) -> tuple[CommandResult, Path]:
    output = out / "nuclei.jsonl"
    cmd = ["nuclei", "-silent", "-j", "-ni", "-rl", str(profile.nuclei_rate), "-c", str(profile.nuclei_concurrency), "-severity", "info,low,medium,high,critical", "-o", str(output)]
    if url_file and url_file.exists() and url_file.stat().st_size:
        cmd += ["-l", str(url_file)]
    else:
        cmd += ["-u", url_from_target(target)]
    return run_command("nuclei", cmd, out), output


def nikto_scan(target: str, out: Path) -> tuple[CommandResult, Path]:
    output = out / "nikto.json"
    cmd = ["nikto", "-h", url_from_target(target), "-nointeractive", "-Format", "json", "-output", str(output)]
    return run_command("nikto", cmd, out, timeout=1800), output


def sqlmap_scan(target: str, out: Path, profile: Profile, url_file: Path | None = None) -> CommandResult:
    sqlout = out / "sqlmap_output"
    sqlout.mkdir(exist_ok=True)
    cmd = ["sqlmap", "--batch", "--level", str(profile.sqlmap_level), "--risk", "1", "--threads", "4", "--output-dir", str(sqlout)]
    if url_file and url_file.exists() and url_file.stat().st_size:
        cmd += ["-m", str(url_file)]
    else:
        cmd += ["-u", url_from_target(target), "--forms"]
    return run_command("sqlmap", cmd, out, timeout=2400)


def tool_versions() -> dict[str, str]:
    checks = {
        "python": ["python3", "--version"],
        "nmap": ["nmap", "--version"],
        "masscan": ["masscan", "--version"],
        "massdns": ["massdns", "--help"],
        "pd-httpx": ["pd-httpx", "-version"],
        "katana": ["katana", "-version"],
        "nuclei": ["nuclei", "-version"],
        "nikto": ["nikto", "-Version"],
        "sqlmap": ["sqlmap", "--version"],
    }
    import subprocess
    result = {}
    for tool, cmd in checks.items():
        if not shutil.which(cmd[0]):
            result[tool] = "MISSING"
            continue
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15, check=False)
            first = next((line.strip() for line in (p.stdout or "").splitlines() if line.strip()), f"exit {p.returncode}")
            result[tool] = first[:180]
        except Exception as e:
            result[tool] = f"ERROR: {e}"
    return result
