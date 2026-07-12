#!/usr/bin/env bash
#
# build-arm64.sh — Build Aquilla-12 (Tauri) natively on a Radxa Rock 5B+ / Armbian GNOME (aarch64).
# Produces a .deb in src-tauri/target/release/bundle/deb/
#
# Usage:   ./build-arm64.sh
# Re-run safe (idempotent-ish): skips deps already present.
#
set -euo pipefail

# ---- pretty output --------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; NC="\033[0m"
info()  { echo -e "${GREEN}==>${NC} ${BOLD}$*${NC}"; }
warn()  { echo -e "${YELLOW}!! ${NC}$*"; }
die()   { echo -e "${RED}xx ${NC}$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- 0. sanity ------------------------------------------------------------
ARCH="$(uname -m)"
info "Detected architecture: ${ARCH}"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  warn "This script is meant to run ON the Rock 5B+ (aarch64). You're on ${ARCH}."
  warn "Native builds only produce a binary for the machine you build on."
  read -rp "Continue anyway? [y/N] " a; [[ "${a,,}" == "y" ]] || exit 1
fi
[[ -f src-tauri/tauri.conf.json ]] || die "Run this from the project root (tauri.conf.json not found)."

# ---- 1. system build dependencies ----------------------------------------
info "Installing system build dependencies (sudo may prompt)..."
sudo apt-get update -y

# Tauri v2 needs the WebKitGTK 4.1 line. Older Armbian bases only ship 4.0.
WEBKIT_PKG=""
if apt-cache show libwebkit2gtk-4.1-dev >/dev/null 2>&1; then
  WEBKIT_PKG="libwebkit2gtk-4.1-dev"
elif apt-cache show libwebkit2gtk-4.0-dev >/dev/null 2>&1; then
  warn "Only WebKitGTK 4.0 is available. Tauri v2 requires 4.1 and the build will likely FAIL."
  warn "Upgrade to a newer Armbian (Debian 12 / Ubuntu 24.04 base) that provides libwebkit2gtk-4.1-dev."
  read -rp "Try anyway with 4.0? [y/N] " a; [[ "${a,,}" == "y" ]] || exit 1
  WEBKIT_PKG="libwebkit2gtk-4.0-dev"
else
  die "No libwebkit2gtk-*-dev package found. Check your apt sources."
fi
info "Using webview package: ${WEBKIT_PKG}"

sudo apt-get install -y \
  build-essential curl wget file pkg-config \
  libssl-dev libgtk-3-dev "${WEBKIT_PKG}" librsvg2-dev \
  libayatana-appindicator3-dev libasound2-dev \
  patchelf desktop-file-utils

# ---- 2. Rust toolchain ----------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  info "Installing Rust toolchain via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
else
  info "Rust already installed: $(cargo --version)"
fi
# make sure cargo is on PATH for this shell
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env" || true

# ---- 3. Node.js (needed for `npm run build` / next export) ----------------
NODE_OK=0
if command -v node >/dev/null 2>&1; then
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
  [[ "$NODE_MAJOR" -ge 20 ]] && NODE_OK=1
fi
if [[ "$NODE_OK" -eq 0 ]]; then
  info "Installing Node.js 20 LTS (NodeSource)..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
else
  info "Node already OK: $(node --version)"
fi

# ---- 4. Frontend + Rust dependencies -------------------------------------
info "Installing npm dependencies..."
npm install

# ---- 5. Build -------------------------------------------------------------
# Restrict bundles to .deb: AppImage bundling is unreliable on ARM.
info "Building Aquilla-12 (this can take 15-40 min on first run)..."
npm run tauri:build -- --bundles deb

# ---- 6. Report ------------------------------------------------------------
DEB="$(find src-tauri/target/release/bundle/deb -name '*.deb' 2>/dev/null | head -n1 || true)"
if [[ -n "$DEB" ]]; then
  info "Build complete!"
  echo -e "  Package: ${BOLD}${DEB}${NC}"
  echo -e "  Install with: ${BOLD}sudo apt install ${DEB}${NC}"
  echo -e "  Or run:       ${BOLD}./install-arm64.sh${NC}"
else
  die "Build finished but no .deb was found. Check the log above for errors."
fi
