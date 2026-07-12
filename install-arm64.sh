#!/usr/bin/env bash
#
# install-arm64.sh — Install the built Aquilla-12 .deb on Armbian GNOME and
# (optionally) set it to auto-start on login. Run after build-arm64.sh.
#
# Usage:   ./install-arm64.sh [--autostart]
#
set -euo pipefail

BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; NC="\033[0m"
info() { echo -e "${GREEN}==>${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}!! ${NC}$*"; }
die()  { echo -e "${RED}xx ${NC}$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

AUTOSTART=0
[[ "${1:-}" == "--autostart" ]] && AUTOSTART=1

# ---- 1. locate the .deb ---------------------------------------------------
DEB="$(find src-tauri/target/release/bundle/deb -name '*.deb' 2>/dev/null | sort | tail -n1 || true)"
[[ -n "$DEB" ]] || die "No .deb found. Run ./build-arm64.sh first."
info "Installing package: ${DEB}"

# ---- 2. install (apt resolves runtime deps automatically) -----------------
sudo apt-get install -y "./$DEB" || {
  warn "apt install failed, falling back to dpkg + fix-broken..."
  sudo dpkg -i "$DEB" || true
  sudo apt-get -f install -y
}

# ---- 3. find installed binary + .desktop ----------------------------------
BIN="$(command -v Aquilla-12 || command -v aquilla-12 || true)"
DESKTOP_FILE="$(ls /usr/share/applications/*quilla* 2>/dev/null | head -n1 || true)"
info "Installed."
[[ -n "$BIN" ]] && echo -e "  Binary:  ${BOLD}${BIN}${NC}"
[[ -n "$DESKTOP_FILE" ]] && echo -e "  Launcher: ${BOLD}${DESKTOP_FILE}${NC}  (also in the GNOME app grid)"

# ---- 4. optional autostart on login --------------------------------------
if [[ "$AUTOSTART" -eq 1 ]]; then
  [[ -n "$DESKTOP_FILE" ]] || die "Cannot set autostart: no .desktop file found."
  mkdir -p "$HOME/.config/autostart"
  cp "$DESKTOP_FILE" "$HOME/.config/autostart/"
  info "Autostart enabled — Aquilla-12 will launch on GNOME login."
  echo -e "  Remove with: ${BOLD}rm ~/.config/autostart/$(basename "$DESKTOP_FILE")${NC}"
fi

info "Done. Launch from the app grid, or run: ${BIN:-Aquilla-12}"
