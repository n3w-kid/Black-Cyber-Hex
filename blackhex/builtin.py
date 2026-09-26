from __future__ import annotations
import ssl
import urllib.error
import urllib.request
from .findings import Finding


def baseline_http(url: str, timeout: int = 10) -> list[Finding]:
    req = urllib.request.Request(url, headers={"User-Agent": "BlackCyberHex/0.1"})
    ctx = ssl.create_default_context()
    out = []
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        final_url = e.geturl()
    except Exception as e:
        return [Finding("builtin", "HTTP baseline check failed", "info", url, str(e), "", "diagnostic")]

    checks = {
        "content-security-policy": "Missing Content-Security-Policy header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
        "referrer-policy": "Missing Referrer-Policy header",
        "permissions-policy": "Missing Permissions-Policy header",
    }
    if final_url.lower().startswith("https://") and "strict-transport-security" not in headers:
        out.append(Finding("builtin", "Missing HSTS header", "low", final_url, "Response did not include strict-transport-security", "", "configuration"))
    for header, title in checks.items():
        if header not in headers:
            sev = "low" if header in {"strict-transport-security", "content-security-policy"} else "info"
            out.append(Finding("builtin", title, sev, final_url, f"Response did not include {header}", "", "configuration"))
    if "server" in headers:
        out.append(Finding("builtin", "Server header disclosed", "info", final_url, headers["server"], "", "information"))
    return out
