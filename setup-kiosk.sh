#!/bin/bash
# ============================================================
# Aquilla-12 Kiosk Mode Setup
# For Armbian Minimal on Rock 5B+
# ============================================================
# This script:
#   1. Hides all boot messages (silent boot)
#   2. Installs cage (minimal Wayland kiosk compositor)
#   3. Auto-logins on tty1 and launches Aquilla-12 fullscreen
#   4. No desktop environment, no login prompt
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "    ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "    ${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "    ${RED}[FAIL]${NC} $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
    fail "Please run as root: sudo $0"
fi

APP_USER="aquilla"

echo ""
echo "============================================================"
echo "  Aquilla-12 Kiosk Mode Setup"
echo "============================================================"
echo ""

# ============================================================
# STEP 1: Find the Aquilla-12 binary
# ============================================================
echo "==> Detecting Aquilla-12 binary..."

APP_BIN=""

# Try to extract from .desktop file first (most reliable)
DESKTOP_FILE=$(find /usr/share/applications -iname "*aquilla*" -o -iname "*Aquilla*" 2>/dev/null | head -1)
if [ -n "$DESKTOP_FILE" ]; then
    EXEC_NAME=$(grep "^Exec=" "$DESKTOP_FILE" | head -1 | sed 's/^Exec=//' | sed 's/ %.*//' | awk '{print $1}')
    # Check if it's an absolute path
    if [ -x "$EXEC_NAME" ]; then
        APP_BIN="$EXEC_NAME"
    # Check if it's just a command name (resolve via PATH)
    elif command -v "$EXEC_NAME" &>/dev/null; then
        APP_BIN="$(command -v "$EXEC_NAME")"
    # Check /usr/bin directly
    elif [ -x "/usr/bin/$EXEC_NAME" ]; then
        APP_BIN="/usr/bin/$EXEC_NAME"
    fi
fi

# Check common binary locations
if [ -z "$APP_BIN" ]; then
    for BIN_PATH in \
        "/usr/bin/app" \
        "/usr/bin/aquilla-12" \
        "/usr/bin/Aquilla-12" \
        "/usr/bin/aquilla12" \
        "/opt/Aquilla-12/aquilla-12"; do
        if [ -x "$BIN_PATH" ]; then
            APP_BIN="$BIN_PATH"
            break
        fi
    done
fi

if [ -z "$APP_BIN" ]; then
    fail "Aquilla-12 binary not found. Install it first: sudo dpkg -i Aquilla-12_*.deb && sudo apt-get -f install -y"
fi

ok "Found: $APP_BIN"

# ============================================================
# STEP 2: Install dependencies
# ============================================================
echo "==> Installing kiosk dependencies..."

apt-get update -qq

# Install cage (Wayland kiosk compositor) and dependencies
apt-get install -y -qq \
    cage seatd \
    libwebkit2gtk-4.1-0 libgtk-3-0 \
    libayatana-appindicator3-1 \
    xdg-utils fonts-noto-core \
    2>/dev/null || {
        warn "Some packages not found, trying alternatives..."
        apt-get install -y -qq cage libwebkit2gtk-4.1-0 libgtk-3-0 2>/dev/null || true
    }

ok "Dependencies installed"

# ============================================================
# STEP 3: Configure seatd for DRM access
# ============================================================
echo "==> Configuring seat access..."

# Enable seatd — this gives cage DRM/GPU access
if systemctl list-unit-files | grep -q seatd; then
    systemctl enable seatd.service
    systemctl start seatd.service 2>/dev/null || true
    ok "seatd enabled"
else
    warn "seatd not available — will use logind"
fi

# Add user to required groups
usermod -aG video,render,input,audio "$APP_USER" 2>/dev/null || true
if getent group _seatd &>/dev/null; then
    usermod -aG _seatd "$APP_USER"
fi
ok "User '$APP_USER' added to video/render/input/audio groups"

# ============================================================
# STEP 4: Silent boot — hide all kernel/console messages
# ============================================================
echo "==> Configuring silent boot..."

ARMBIAN_ENV="/boot/armbianEnv.txt"
if [ -f "$ARMBIAN_ENV" ]; then
    # Remove old extraargs if present, add silent boot params
    sed -i '/^extraargs=/d' "$ARMBIAN_ENV"
    echo 'extraargs=quiet splash loglevel=0 vt.global_cursor_default=0 logo.nologo consoleblank=1' >> "$ARMBIAN_ENV"
    ok "Kernel boot params configured"
fi

# Suppress kernel console messages
if [ -f /etc/sysctl.conf ]; then
    sed -i '/kernel.printk/d' /etc/sysctl.conf
    echo 'kernel.printk = 0 0 0 0' >> /etc/sysctl.conf
fi

# Clear login banners
cp /etc/issue /etc/issue.bak 2>/dev/null || true
echo "" > /etc/issue
echo "" > /etc/issue.net
ok "Boot messages suppressed"

# ============================================================
# STEP 5: Configure auto-login on tty1
# ============================================================
echo "==> Configuring auto-login on tty1..."

# Create getty override for auto-login
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf << GETTYEOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $APP_USER --noclear %I \$TERM
Type=idle
GETTYEOF

ok "Auto-login configured for user '$APP_USER' on tty1"

# ============================================================
# STEP 6: Create kiosk launcher in user profile
# ============================================================
echo "==> Creating kiosk launcher..."

USER_HOME="/home/$APP_USER"

# Create the kiosk launch script
cat > "$USER_HOME/kiosk-start.sh" << KIOSKEOF
#!/bin/bash
# Aquilla-12 Kiosk Launcher
# This script is called from .bash_profile on tty1

export XDG_RUNTIME_DIR="/run/user/\$(id -u)"
export LIBSEAT_BACKEND=seatd
# --- Software rendering (REQUIRED on this image) ---------------------------
# The RK3588 Mali GPU has no working EGL/GLES driver in the vendor-kernel
# Armbian image, so cage's default GLES2 renderer fails with
#   "Failed to create a GLES2 renderer / Unable to create the wlroots renderer"
# and the screen stays blank. Pixman renders on the CPU — slower but reliable.
# The matching WebKit/GDK flags stop the WebView from trying (and failing) GL.
export WLR_RENDERER=pixman
export LIBGL_ALWAYS_SOFTWARE=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export GDK_GL=disable
export GDK_BACKEND=wayland
# Audio output is chosen in the Aquilla console (Settings → Audio Output
# Interface) and persisted per-device. Do NOT export AQUILLA_OUTPUT_DEVICE
# here — it is a hard override that would defeat the console selector. Set it
# only if you want to force a fixed output regardless of the console.

# Create runtime dir if it doesn't exist
mkdir -p "\$XDG_RUNTIME_DIR" 2>/dev/null || true

# Wait for seatd to be ready
sleep 1

# Wait (up to 20s) for the USB touchscreen to enumerate BEFORE launching cage.
# cage scans input devices once at startup; if it starts before the panel is
# up, touch won't work until a restart. This blocks until a touchscreen exists.
for _ in \$(seq 1 20); do
    for d in /dev/input/event*; do
        [ -e "\$d" ] || continue
        if udevadm info --query=property "\$d" 2>/dev/null | grep -q '^ID_INPUT_TOUCHSCREEN=1'; then
            touch_ready=1
            break
        fi
    done
    [ "\${touch_ready:-}" = "1" ] && break
    sleep 1
done

# Launch cage with Aquilla-12 in fullscreen
exec cage -s -- $APP_BIN
KIOSKEOF

chmod +x "$USER_HOME/kiosk-start.sh"
chown "$APP_USER:$APP_USER" "$USER_HOME/kiosk-start.sh"
ok "Kiosk launcher created at $USER_HOME/kiosk-start.sh"

# Add kiosk launch to .bash_profile (only on tty1)
PROFILE="$USER_HOME/.bash_profile"

# Backup existing profile
cp "$PROFILE" "${PROFILE}.bak" 2>/dev/null || true

# Remove any previous kiosk block
sed -i '/# --- AQUILLA KIOSK START ---/,/# --- AQUILLA KIOSK END ---/d' "$PROFILE" 2>/dev/null || true

# Append kiosk auto-start block
cat >> "$PROFILE" << 'PROFILEEOF'

# --- AQUILLA KIOSK START ---
# Auto-start kiosk mode on tty1 only
if [ "$(tty)" = "/dev/tty1" ] && [ -z "$WAYLAND_DISPLAY" ]; then
    exec ~/kiosk-start.sh
fi
# --- AQUILLA KIOSK END ---
PROFILEEOF

chown "$APP_USER:$APP_USER" "$PROFILE"
ok "Auto-start added to .bash_profile (tty1 only)"

# ============================================================
# STEP 7: Disable the old systemd kiosk service (if exists)
# ============================================================
if systemctl is-enabled aquilla-kiosk.service &>/dev/null; then
    systemctl disable aquilla-kiosk.service
    systemctl stop aquilla-kiosk.service 2>/dev/null || true
    ok "Disabled old aquilla-kiosk.service"
fi

# ============================================================
# STEP 8: Blank console before compositor starts
# ============================================================
echo "==> Configuring pre-boot blank screen..."

cat > /etc/systemd/system/blank-console.service << 'BLANKEOF'
[Unit]
Description=Blank Console Screen
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'setterm --blank force --term linux < /dev/tty1 > /dev/tty1 2>&1 || true'

[Install]
WantedBy=sysinit.target
BLANKEOF

systemctl enable blank-console.service 2>/dev/null || true
ok "Console blank service enabled"

# ============================================================
# STEP 9: Ensure XDG_RUNTIME_DIR exists at boot
# ============================================================
echo "==> Configuring runtime directory..."

UID_NUM=$(id -u "$APP_USER")
mkdir -p /etc/tmpfiles.d
cat > /etc/tmpfiles.d/aquilla-xdg.conf << TMPEOF
d /run/user/$UID_NUM 0700 $APP_USER $APP_USER -
TMPEOF

ok "XDG runtime directory configured"

# ============================================================
# DONE
# ============================================================
systemctl daemon-reload

echo ""
echo "============================================================"
echo -e "  ${GREEN}Aquilla-12 Kiosk Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  App Binary:  $APP_BIN"
echo "  Compositor:  cage (Wayland)"
echo "  Auto-login:  tty1 → user '$APP_USER'"
echo "  Launcher:    $USER_HOME/kiosk-start.sh"
echo ""
echo "  Boot sequence:"
echo "    1. Silent boot (no text visible)"
echo "    2. Auto-login on tty1"
echo "    3. cage launches Aquilla-12 fullscreen"
echo ""
echo "  Useful commands (via SSH):"
echo "    Check logs:  journalctl -b | grep -i cage"
echo "    Restart:     sudo systemctl restart getty@tty1"
echo "    Disable:     sudo rm /etc/systemd/system/getty@tty1.service.d/autologin.conf"
echo ""
echo -e "  ${YELLOW}Reboot now: sudo reboot${NC}"
echo "============================================================"
