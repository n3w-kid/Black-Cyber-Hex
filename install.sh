#!/usr/bin/env bash
set -euo pipefail

BASE="${XDG_DATA_HOME:-$HOME/.local/share}/black-cyber-hex"
mkdir -p "$BASE/bin" "$BASE/src"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  python3 python3-venv nmap masscan git make gcc perl libnet-ssleay-perl ca-certificates curl tar

version_ge() {
  # true when $1 >= $2
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

ensure_modern_go() {
  local need="1.25.0" current="" arch="" gov=""
  if command -v go >/dev/null 2>&1; then
    current="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' || true)"
  fi
  if [[ -n "$current" ]] && version_ge "$current" "$need"; then
    return 0
  fi

  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "[!] Unsupported architecture for automatic Go install: $(uname -m)" >&2; return 1 ;;
  esac

  gov="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)"
  [[ "$gov" == go* ]] || { echo "[!] Could not determine current Go release" >&2; return 1; }
  echo "[*] Installing $gov locally for current ProjectDiscovery tools..."
  rm -rf "$BASE/go"
  curl -fsSL "https://go.dev/dl/${gov}.linux-${arch}.tar.gz" | tar -C "$BASE" -xz
  export PATH="$BASE/go/bin:$PATH"
}

if ! command -v massdns >/dev/null 2>&1; then
  rm -rf "$BASE/src/massdns"
  git clone --depth=1 https://github.com/blechschmidt/massdns.git "$BASE/src/massdns"
  make -C "$BASE/src/massdns"
  install -m755 "$BASE/src/massdns/bin/massdns" "$BASE/bin/massdns"
fi

if ! command -v pd-httpx >/dev/null 2>&1 || ! command -v katana >/dev/null 2>&1 || ! command -v nuclei >/dev/null 2>&1; then
  ensure_modern_go
fi
if ! command -v pd-httpx >/dev/null 2>&1; then
  GOBIN="$BASE/bin" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  mv -f "$BASE/bin/httpx" "$BASE/bin/pd-httpx"
fi
if ! command -v katana >/dev/null 2>&1; then
  GOBIN="$BASE/bin" go install github.com/projectdiscovery/katana/cmd/katana@latest
fi
if ! command -v nuclei >/dev/null 2>&1; then
  GOBIN="$BASE/bin" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

if ! command -v sqlmap >/dev/null 2>&1; then
  rm -rf "$BASE/src/sqlmap"
  git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git "$BASE/src/sqlmap"
  cat > "$BASE/bin/sqlmap" <<EOF
#!/usr/bin/env sh
exec python3 "$BASE/src/sqlmap/sqlmap.py" "\$@"
EOF
  chmod +x "$BASE/bin/sqlmap"
fi

if ! command -v nikto >/dev/null 2>&1; then
  rm -rf "$BASE/src/nikto"
  git clone --depth=1 https://github.com/sullo/nikto.git "$BASE/src/nikto"
  cat > "$BASE/bin/nikto" <<EOF
#!/usr/bin/env sh
exec perl "$BASE/src/nikto/program/nikto.pl" "\$@"
EOF
  chmod +x "$BASE/bin/nikto"
fi

if [[ ":$PATH:" != *":$BASE/bin:"* ]]; then
  echo
  echo "Add this to your shell profile:"
  echo "  export PATH=\"$BASE/bin:\$PATH\""
fi

echo "[+] Installed external tools under $BASE"
echo "[+] Run: PATH=\"$BASE/bin:\$PATH\" python3 bch.py doctor"
echo "[+] Then: PATH=\"$BASE/bin:\$PATH\" python3 bch.py"
