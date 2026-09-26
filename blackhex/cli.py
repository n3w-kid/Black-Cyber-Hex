from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from .banner import banner
from .builtin import baseline_http
from .config import DEFAULT_PROFILE, PROFILES
from .orchestrator import full_scan, make_run_dir
from .parsers import parse_httpx, parse_katana, parse_masscan, parse_massdns, parse_nikto, parse_nmap, parse_nuclei, parse_sqlmap
from .report import write_report
from .scope import normalize_target, url_from_target, host_from_target
from .tools import httpx_probe, katana_scan, masscan_scan, massdns_scan, nikto_scan, nmap_scan, nuclei_scan, sqlmap_scan, tool_versions


AUTH_PHRASE = "I HAVE AUTHORIZATION"


def require_authorization(args) -> None:
    if getattr(args, "authorized", False):
        return
    if not sys.stdin.isatty():
        raise SystemExit("Active scans require --authorized to confirm you have permission for the target.")
    print("\nThis framework performs active security testing. Use it only on systems you own or are explicitly authorized to test.")
    typed = input(f"Type '{AUTH_PHRASE}' to continue: ").strip()
    if typed != AUTH_PHRASE:
        raise SystemExit("Authorization confirmation not provided.")


def profile_for(args):
    return PROFILES[getattr(args, "profile", DEFAULT_PROFILE)]


def _single_report(target, out, findings, run):
    runs = [run.to_dict()] if run else []
    jp, mp = write_report(out, target, findings, runs)
    print(f"\n[+] JSON report: {jp}")
    print(f"[+] Markdown report: {mp}")


def run_single(args):
    require_authorization(args)
    target = normalize_target(args.target)
    profile = profile_for(args)
    out = make_run_dir(Path(args.output), target)
    findings = baseline_http(url_from_target(target)) if args.command == "baseline" else []
    run = None

    if args.command == "baseline":
        _single_report(target, out, findings, run)
        return
    if args.command == "nmap":
        run, p = nmap_scan(target, out, profile, vuln=args.vuln, all_ports=args.all_ports, intrusive=args.intrusive_nse)
        findings += parse_nmap(p)
    elif args.command == "masscan":
        run, p = masscan_scan(target, out, profile, args.ports)
        findings += parse_masscan(p)
    elif args.command == "dns":
        host = host_from_target(target)
        import ipaddress
        try:
            ipaddress.ip_address(host)
            raise ValueError("MassDNS mode expects a domain name or a candidate FQDN list, not a raw IP address.")
        except ValueError as exc:
            if str(exc).startswith("MassDNS mode"):
                raise
        run, p = massdns_scan(target, out, Path(args.resolvers) if args.resolvers else None, Path(args.candidates) if args.candidates else None)
        findings += parse_massdns(p)
    elif args.command == "httpx":
        run, p = httpx_probe(target, out, profile)
        f, _ = parse_httpx(p)
        findings += f
    elif args.command == "crawl":
        run, p = katana_scan(target, out, profile)
        f, _ = parse_katana(p)
        findings += f
    elif args.command == "nuclei":
        run, p = nuclei_scan(target, out, profile)
        findings += parse_nuclei(p)
    elif args.command == "nikto":
        run, p = nikto_scan(target, out)
        findings += parse_nikto(p)
    elif args.command == "sqlmap":
        run = sqlmap_scan(target, out, profile)
        findings += parse_sqlmap(Path(run.stdout_file), target)
    _single_report(target, out, findings, run)


def run_full(args):
    require_authorization(args)
    target = normalize_target(args.target)
    out, findings = full_scan(target, Path(args.output), profile_for(args), args.masscan, not args.no_dns, args.intrusive_nse)
    print(f"\n[+] Scan complete: {out}")
    print(f"[+] Normalized findings: {len(findings)}")
    print(f"[+] Open: {out / 'summary.md'}")


def update_tools():
    tasks = [
        ("Nuclei templates", ["nuclei", "-ut"]),
        ("Nmap NSE script database", ["nmap", "--script-updatedb"]),
    ]
    for name, cmd in tasks:
        print(f"[*] {name}")
        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            print(f"    missing: {cmd[0]}")
    data_root = Path(os.getenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "black-cyber-hex" / "src"
    repos = {
        "Nikto": [Path("/opt/nikto"), data_root / "nikto"],
        "sqlmap": [Path("/opt/sqlmap"), data_root / "sqlmap"],
    }
    for name, candidates in repos.items():
        repo = next((x for x in candidates if (x / ".git").exists()), None)
        if repo and shutil.which("git"):
            print(f"[*] {name} git checkout: {repo}")
            subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"], check=False)
        else:
            print(f"[*] {name}: update its git checkout or rebuild the Docker image.")
    print("[*] Rebuild the Docker image to refresh Nmap, Masscan, MassDNS, ProjectDiscovery HTTPX, Katana, and Nuclei engine binaries.")


def doctor():
    print("\nTool health\n-----------")
    for tool, version in tool_versions().items():
        state = "OK" if version != "MISSING" and not version.startswith("ERROR") else "!!"
        print(f"[{state}] {tool:9} {version}")


def interactive():
    while True:
        banner()
        print("  1) Quick/full web scan (recommended)")
        print("  2) Nmap ports + service detection")
        print("  3) Nmap safe vulnerability scan (NSE + Vulners)")
        print("  4) Masscan fast port discovery")
        print("  5) MassDNS DNS resolution / subdomain candidates")
        print("  6) HTTPX live web / technology probe")
        print("  7) Katana crawler")
        print("  8) Nuclei template scan")
        print("  9) Nikto web server scan")
        print(" 10) sqlmap SQL injection detection")
        print(" 11) Tool health / versions")
        print(" 12) Update scanner databases/templates")
        print("  0) Exit")
        choice = input("\nblackhex> ").strip()
        if choice == "0":
            return
        if choice == "11":
            doctor(); input("\nPress Enter..."); continue
        if choice == "12":
            update_tools(); input("\nPress Enter..."); continue
        if choice not in {str(i) for i in range(1, 11)}:
            print("Unknown option."); continue
        target = input("Target (URL / hostname / IP / CIDR): ").strip()
        profile = input("Profile [safe/balanced/fast] (balanced): ").strip() or DEFAULT_PROFILE
        if profile not in PROFILES:
            profile = DEFAULT_PROFILE
        base = argparse.Namespace(target=target, output="reports", profile=profile, authorized=False, intrusive_nse=False)
        try:
            if choice == "1":
                base.masscan = input("Include Masscan? [y/N]: ").lower().startswith("y")
                base.no_dns = False
                run_full(base)
            elif choice == "2":
                base.command="nmap"; base.vuln=False; base.all_ports=input("All 65535 TCP ports? [y/N]: ").lower().startswith("y"); run_single(base)
            elif choice == "3":
                base.command="nmap"; base.vuln=True; base.all_ports=False; run_single(base)
            elif choice == "4":
                base.command="masscan"; base.ports=input("Ports (default web ports): ").strip() or "80,443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443"; run_single(base)
            elif choice == "5":
                base.command="dns"; base.resolvers=None; base.candidates=None; run_single(base)
            elif choice == "6": base.command="httpx"; run_single(base)
            elif choice == "7": base.command="crawl"; run_single(base)
            elif choice == "8": base.command="nuclei"; run_single(base)
            elif choice == "9": base.command="nikto"; run_single(base)
            elif choice == "10": base.command="sqlmap"; run_single(base)
        except (ValueError, SystemExit) as e:
            print(f"[!] {e}")
        input("\nPress Enter to return to menu...")


def build_parser():
    p = argparse.ArgumentParser(prog="black-cyber-hex", description="Black Cyber Hex — authorized web security scanning orchestrator")
    p.add_argument("--output", default="reports", help="base report directory")
    p.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    sub = p.add_subparsers(dest="command")

    def active(name, helptext):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("target")
        sp.add_argument("--authorized", action="store_true", help="confirm explicit authorization for this target")
        return sp

    s = active("scan", "combined web scan")
    s.add_argument("--masscan", action="store_true", help="add fast Masscan discovery before Nmap validation")
    s.add_argument("--no-dns", action="store_true")
    s.add_argument("--intrusive-nse", action="store_true", help="use full Nmap vuln category instead of safe-only vuln scripts")

    s = active("baseline", "built-in HTTP header baseline")
    s = active("nmap", "Nmap port/service or vulnerability scan")
    s.add_argument("--vuln", action="store_true")
    s.add_argument("--all-ports", action="store_true")
    s.add_argument("--intrusive-nse", action="store_true")

    s = active("masscan", "Masscan fast port discovery")
    s.add_argument("--ports", default="80,443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443")
    s = active("dns", "MassDNS resolution")
    s.add_argument("--resolvers")
    s.add_argument("--candidates", help="file containing FQDNs to resolve")
    active("httpx", "HTTPX live web / technology probe")
    active("crawl", "Katana crawler")
    active("nuclei", "Nuclei vulnerability templates")
    active("nikto", "Nikto web scan")
    active("sqlmap", "sqlmap SQLi detection")
    sub.add_parser("doctor", help="show tool availability/versions")
    sub.add_parser("update", help="update templates / scanner databases")
    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if args.command is None:
        interactive()
    elif args.command == "doctor":
        banner(); doctor()
    elif args.command == "update":
        banner(); update_tools()
    elif args.command == "scan":
        banner(); run_full(args)
    else:
        banner(); run_single(args)
