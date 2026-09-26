from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    nmap_timing: str
    nmap_top_ports: int
    masscan_rate: int
    katana_depth: int
    katana_rate: int
    httpx_rate: int
    nuclei_rate: int
    nuclei_concurrency: int
    sqlmap_level: int
    max_sqlmap_urls: int


PROFILES = {
    "safe": Profile("safe", "T2", 500, 200, 2, 10, 15, 25, 10, 1, 8),
    "balanced": Profile("balanced", "T3", 1000, 1000, 3, 30, 40, 75, 20, 2, 15),
    "fast": Profile("fast", "T4", 2000, 3000, 4, 80, 100, 150, 30, 2, 25),
}

DEFAULT_PROFILE = "balanced"
WEB_PORTS = "80,443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443"
COMMON_SUBDOMAINS = [
    "www", "api", "admin", "app", "auth", "dev", "staging", "test",
    "portal", "mail", "cdn", "static", "assets", "beta", "internal",
]
