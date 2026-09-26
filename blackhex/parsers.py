from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from .findings import Finding


def parse_nmap(xml_path: Path) -> list[Finding]:
    if not xml_path.exists() or not xml_path.stat().st_size:
        return []
    out: list[Finding] = []
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return out
    for host in root.findall("host"):
        addr = ""
        addr_el = host.find("address")
        if addr_el is not None:
            addr = addr_el.attrib.get("addr", "")
        names = [x.attrib.get("name", "") for x in host.findall("hostnames/hostname") if x.attrib.get("name")]
        display = names[0] if names else addr
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            proto = port.attrib.get("protocol", "tcp")
            portid = port.attrib.get("portid", "")
            svc = port.find("service")
            service = svc.attrib.get("name", "unknown") if svc is not None else "unknown"
            product = svc.attrib.get("product", "") if svc is not None else ""
            version = svc.attrib.get("version", "") if svc is not None else ""
            cpe = [x.text for x in (svc.findall("cpe") if svc is not None else []) if x.text]
            evidence = " ".join(x for x in [service, product, version] if x).strip()
            out.append(Finding("nmap", f"Open {proto}/{portid} ({service})", "info", display, evidence, cpe[0] if cpe else "", "service"))
            for script in port.findall("script"):
                sid = script.attrib.get("id", "NSE")
                text = script.attrib.get("output", "").strip()
                severity = "medium" if sid != "vulners" else "info"
                if re.search(r"\b(CRITICAL|CVSS:\s*(9|10)|CVSS\s+9)", text, re.I):
                    severity = "critical"
                elif re.search(r"CVSS[:\s]+[7-8](?:\.\d+)?", text, re.I):
                    severity = "high"
                out.append(Finding("nmap-nse", sid, severity, f"{display}:{portid}", text[:4000], "", "vulnerability"))
    return out


def _json_lines(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().rstrip(",")
        if not line or line in {"[", "]"}:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_nuclei(path: Path) -> list[Finding]:
    out = []
    for row in _json_lines(path) or []:
        info = row.get("info") or {}
        sev = str(info.get("severity") or "unknown").lower()
        title = str(info.get("name") or row.get("template-id") or "Nuclei finding")
        target = str(row.get("matched-at") or row.get("host") or "")
        ref = str(row.get("template-id") or "")
        evidence = str(row.get("matcher-name") or "")
        extracted = row.get("extracted-results") or []
        if extracted:
            evidence = (evidence + " | " + ", ".join(map(str, extracted)))[:4000]
        out.append(Finding("nuclei", title, sev, target, evidence, ref, "vulnerability", {"type": row.get("type")}))
    return out


def parse_katana(path: Path) -> tuple[list[Finding], list[str]]:
    out = []
    urls = []
    for row in _json_lines(path) or []:
        req = row.get("request") or {}
        url = req.get("endpoint") or row.get("url") or row.get("endpoint")
        if url and isinstance(url, str):
            urls.append(url)
    for url in sorted(set(urls)):
        out.append(Finding("katana", "Discovered endpoint", "info", url, "", "", "endpoint"))
    return out, sorted(set(urls))


def parse_massdns(path: Path) -> list[Finding]:
    out = []
    for row in _json_lines(path) or []:
        name = str(row.get("name") or row.get("question", {}).get("name") or "")
        answers = row.get("data", {}).get("answers") or row.get("answers") or []
        values = []
        for a in answers:
            if isinstance(a, dict):
                values.append(str(a.get("data") or a.get("answer") or a))
            else:
                values.append(str(a))
        if values:
            out.append(Finding("massdns", "Resolved DNS name", "info", name.rstrip("."), ", ".join(values)[:2000], "", "dns"))
    return out


def parse_httpx(path: Path) -> tuple[list[Finding], list[str]]:
    out: list[Finding] = []
    urls: list[str] = []
    for row in _json_lines(path) or []:
        url = str(row.get("url") or row.get("input") or "")
        if not url:
            continue
        urls.append(url)
        status = row.get("status_code")
        title = row.get("title") or ""
        tech = row.get("tech") or row.get("technologies") or []
        server = row.get("webserver") or row.get("server") or ""
        if isinstance(tech, list):
            tech_text = ", ".join(map(str, tech))
        else:
            tech_text = str(tech)
        evidence = " | ".join(x for x in [f"status={status}" if status is not None else "", f"title={title}" if title else "", f"server={server}" if server else "", f"tech={tech_text}" if tech_text else ""] if x)
        out.append(Finding("httpx", "Live HTTP service", "info", url, evidence, "", "service"))
    return out, sorted(set(urls))


def parse_masscan(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    try:
        rows = json.loads(text)
    except Exception:
        rows = []
        for row in _json_lines(path) or []:
            rows.append(row)
    out = []
    for row in rows if isinstance(rows, list) else []:
        ip = str(row.get("ip") or "")
        for p in row.get("ports") or []:
            if p.get("status") == "open":
                port = p.get("port")
                proto = p.get("proto", "tcp")
                out.append(Finding("masscan", f"Open {proto}/{port}", "info", ip, "Fast discovery; validate with Nmap.", "", "service"))
    return out


def parse_nikto(path: Path) -> list[Finding]:
    if not path.exists() or not path.stat().st_size:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out: list[Finding] = []

    def walk(obj, context=""):
        if isinstance(obj, dict):
            msg = obj.get("msg") or obj.get("message") or obj.get("description")
            uri = obj.get("uri") or obj.get("url") or obj.get("host") or context
            osvdb = obj.get("osvdb") or obj.get("id") or ""
            if isinstance(msg, str) and msg.strip():
                lower = msg.lower()
                sev = "medium" if any(k in lower for k in ["vulnerab", "remote", "injection", "xss", "traversal"]) else "low"
                out.append(Finding("nikto", msg.strip()[:240], sev, str(uri), msg.strip()[:4000], str(osvdb), "web"))
            for v in obj.values():
                walk(v, str(uri) if uri else context)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, context)

    walk(data)
    return out


def parse_sqlmap(stdout_path: Path, target: str) -> list[Finding]:
    if not stdout_path.exists():
        return []
    text = stdout_path.read_text(encoding="utf-8", errors="replace")
    patterns = [
        r"sqlmap identified the following injection point",
        r"parameter ['\"].+?['\"] is vulnerable",
        r"is vulnerable\. Do you want to keep testing",
    ]
    if any(re.search(p, text, re.I) for p in patterns):
        snippets = []
        for line in text.splitlines():
            if re.search(r"(Parameter:|Type:|Title:|Payload:|is vulnerable|identified the following)", line, re.I):
                snippets.append(line.strip())
        return [Finding("sqlmap", "SQL injection detected", "high", target, "\n".join(snippets)[:6000], "", "vulnerability")]
    return []
