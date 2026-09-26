from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("target is empty")
    if "://" in value:
        p = urlparse(value)
        if p.scheme not in {"http", "https"} or not p.hostname:
            raise ValueError("target URL must be http:// or https://")
        return value.rstrip("/")
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if not HOST_RE.match(value):
        raise ValueError("target must be a hostname, IP, CIDR, or HTTP(S) URL")
    return value.rstrip("/")


def host_from_target(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    if "/" in target:
        return target.split("/", 1)[0]
    if target.startswith("[") and "]" in target:
        return target[1:target.index("]")]
    return target.split(":", 1)[0]


def url_from_target(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    host = host_from_target(target)
    try:
        ipaddress.ip_network(target, strict=False)
        return f"https://{host}"
    except ValueError:
        return f"https://{target}"


@dataclass
class Scope:
    root: str

    def allows_host(self, host: str) -> bool:
        root = host_from_target(self.root).lower().rstrip(".")
        host = (host or "").lower().rstrip(".")
        try:
            net = ipaddress.ip_network(self.root, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            pass
        if host == root:
            return True
        return host.endswith("." + root)

    def allows_url(self, url: str) -> bool:
        try:
            return self.allows_host(urlparse(url).hostname or "")
        except Exception:
            return False
