#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:?usage: $0 target}"
# Safe vulnerability category + Nmap's built-in Vulners integration.
exec nmap -Pn -sV --version-light --script 'vulners,(vuln and safe)' -p 80,443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443 "$TARGET"
