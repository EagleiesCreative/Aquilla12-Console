#!/usr/bin/env bash
# ============================================================
# deploy-to-sbc.sh — Build Aquilla-12 on the ARM64 GNOME build
# board, then ship + install it on the minimal kiosk board.
# Run this FROM YOUR MAC.
# ============================================================
#
# Flow (two-board):
#   Mac ──rsync──▶ BUILD board (GNOME, compiles the .deb)
#   BUILD ──scp──▶ Mac (pulls the freshly built .deb back)
#   Mac ──scp──▶ KIOSK board (.deb + updated setup scripts + HID files)
#   Mac ──ssh──▶ KIOSK board (install .deb, rerun audio+kiosk setup, reboot)
#
# The audio-output change is opt-in: after this deploy the DAC is NO longer
# auto-forced. Rerunning setup-max98357a.sh here strips any old
# AQUILLA_OUTPUT_DEVICE override so the console's "Audio Output Interface"
# selector controls routing. Select MAX98357A in the console after reboot.
#
# Usage:
#   chmod +x deploy-to-sbc.sh
#   ./deploy-to-sbc.sh            # full build + deploy
#   ./deploy-to-sbc.sh --no-build # skip the remote build, deploy the last .deb
#
# Prereqs: SSH access (ideally key-based) to both boards from this Mac.
# ============================================================
set -euo pipefail

# ---- CONFIG — EDIT THESE ----------------------------------------------------
BUILD_HOST="aquilla@rock-5b-plus.local"      # GNOME board that compiles the .deb
KIOSK_HOST="aquilla@192.168.20.4"            # minimal kiosk board (the target SBC)
KIOSK_APP_BIN="/usr/bin/app"                 # installed binary path (Tauri config)
RERUN_KIOSK_SETUP=1                          # 1 = also rerun setup-kiosk.sh on the kiosk board
# ---------------------------------------------------------------------------

LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_BUILD_DIR='SIP Controller'            # relative to home on the BUILD board (no ~ so it quotes cleanly)
DEB_REL="src-tauri/target/release/bundle/deb"
DO_BUILD=1
[[ "${1:-}" == "--no-build" ]] && DO_BUILD=0

BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; NC="\033[0m"
info() { echo -e "\n${GREEN}==>${NC} ${BOLD}$*${NC}"; }
warn() { echo -e "${YELLOW}!! ${NC}$*"; }
die()  { echo -e "${RED}xx ${NC}$*" >&2; exit 1; }

command -v rsync >/dev/null || die "rsync not found on this Mac."
command -v ssh   >/dev/null || die "ssh not found on this Mac."

# ---- 1. Sync source to the build board -------------------------------------
if [[ "$DO_BUILD" -eq 1 ]]; then
  info "Syncing source → build board ($BUILD_HOST)"
  ssh "$BUILD_HOST" "mkdir -p \"$REMOTE_BUILD_DIR\""
  rsync -av --delete \
    --exclude node_modules --exclude .next --exclude out \
    --exclude 'src-tauri/target' --exclude .git \
    "$LOCAL_DIR/" "$BUILD_HOST:$REMOTE_BUILD_DIR/"

  # ---- 2. Build the .deb on the build board --------------------------------
  info "Building the .deb on the build board (15–40 min on a cold build)…"
  ssh "$BUILD_HOST" "cd \"$REMOTE_BUILD_DIR\" && chmod +x build-arm64.sh && ./build-arm64.sh"
fi

# ---- 3. Locate + pull the freshly built .deb -------------------------------
info "Locating the built package on the build board"
DEB_REMOTE="$(ssh "$BUILD_HOST" "ls -t \"$REMOTE_BUILD_DIR/$DEB_REL\"/*.deb 2>/dev/null | head -n1" || true)"
[[ -n "$DEB_REMOTE" ]] || die "No .deb found on build board under $DEB_REL. Did the build succeed?"
DEB_NAME="$(basename "$DEB_REMOTE")"
info "Pulling $DEB_NAME → Mac"
scp "$BUILD_HOST:\"$DEB_REMOTE\"" "$LOCAL_DIR/$DEB_NAME"

# ---- 4. Push package + updated setup files to the kiosk board --------------
info "Clearing any stale SSH host key for the kiosk board (safe if unchanged)"
KIOSK_ADDR="${KIOSK_HOST##*@}"
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$KIOSK_ADDR" >/dev/null 2>&1 || true

info "Uploading package + updated scripts → kiosk board ($KIOSK_HOST)"
scp "$LOCAL_DIR/$DEB_NAME" \
    "$LOCAL_DIR/setup-max98357a.sh" \
    "$LOCAL_DIR/setup-kiosk.sh" \
    "$LOCAL_DIR/hid_panel_config.json" \
    "$KIOSK_HOST:~/"
ssh "$KIOSK_HOST" 'mkdir -p ~/packaging/udev'
scp "$LOCAL_DIR/packaging/udev/60-aquilla12-hid.rules" \
    "$KIOSK_HOST:~/packaging/udev/"

# ---- 5. Install + reconfigure on the kiosk board ---------------------------
info "Installing on the kiosk board and reconfiguring audio (opt-in DAC)…"
ssh -t "$KIOSK_HOST" "bash -s" <<EOF
set -e
echo '==> Installing the .deb…'
sudo dpkg -i ~/$DEB_NAME || true
sudo apt-get -f install -y

echo '==> Re-running I2S audio setup (DAC becomes selectable, not forced)…'
chmod +x ~/setup-max98357a.sh
sudo ~/setup-max98357a.sh

if [ "$RERUN_KIOSK_SETUP" -eq 1 ]; then
  echo '==> Re-running kiosk setup (regenerates launcher without the forced env)…'
  sed -i 's|APP_BIN=""|APP_BIN="$KIOSK_APP_BIN"|' ~/setup-kiosk.sh
  chmod +x ~/setup-kiosk.sh
  sudo ~/setup-kiosk.sh
fi

echo '==> Reinstalling HID udev rule…'
sudo cp ~/packaging/udev/60-aquilla12-hid.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger

echo '==> Done on the kiosk board. Rebooting in 5s (Ctrl-C to cancel)…'
sleep 5
sudo reboot -f
EOF

info "Deploy complete."
echo -e "  After the kiosk board reboots:"
echo -e "    • Open the Aquilla console → ${BOLD}Settings → Audio Output Interface${NC}"
echo -e "    • Select ${BOLD}MAX98357A${NC} to route call audio to the I2S DAC"
echo -e "    • Leave it on ${BOLD}System Default (SBC onboard)${NC} for onboard audio"
