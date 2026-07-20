#!/bin/bash
# ============================================================
# MAX98357A I2S DAC Setup for Rock 5B+ (Armbian) — v2, VERIFIED WORKING
# ============================================================
# Verified end-to-end on 2026-07-20 against:
#   Armbian vendor kernel 6.1.115-vendor-rk35xx, ROCK 5B+ (kiosk board)
#
# What changed vs v1 (max98357a-overlay):
#   * Uses the real `maxim,max98357a` codec driver (built from source —
#     the vendor kernel does NOT ship snd-soc-max98357a) instead of the
#     linux,spdif-dit dummy codec.
#   * Uses the stock i2s2_2ch node config (no hand-patched clock IDs).
#   * Card is named "Aquilla Speakers" (ALSA card ID: `Speakers` — ALSA
#     derives the ID itself and shortens it; use hw:Speakers).
#   * The DAC IS the system default output: any ALSA app, including the
#     Aquilla console on "System Default", plays through the speaker.
#   * Removes the old broken `max98357a-overlay` if present — leaving it
#     in user_overlays aborts U-Boot's overlay chain and the card vanishes.
#
# Wiring (40-pin header):
#   BCLK  → Pin 12 (GPIO3_B5 / I2S2_SCLK_M1)
#   LRCK  → Pin 35 (GPIO3_B6 / I2S2_LRCK_M1)
#   DIN   → Pin 40 (GPIO3_B3 / I2S2_SDO_M1)
#   VIN   → Pin 2 or 4 (5V)
#   GND   → Pin 6, 9, 14, 20, 25, 30, 34, or 39
#   SD    → Pin 17 (3.3V), or leave floating on Adafruit-style
#           breakouts (they pull it up). Low = silent.
#
# Usage:
#   sudo bash setup-max98357a.sh
#   sudo reboot
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
    fail "Please run as root: sudo bash $0"
fi

echo ""
echo "============================================================"
echo "  MAX98357A / Aquilla Speakers Setup for Rock 5B+  (v2)"
echo "============================================================"
echo ""

ARMBIAN_ENV="/boot/armbianEnv.txt"
[ -f "$ARMBIAN_ENV" ] || fail "$ARMBIAN_ENV not found — is this Armbian?"

# ============================================================
# STEP 1: Remove the old broken v1 overlay (CRITICAL)
# ============================================================
# If U-Boot fails to apply any overlay in user_overlays it can abort the
# whole chain, so a stale max98357a-overlay.dtbo silently disables the
# new one too. This was the root cause of "card never appears".
echo "==> Removing stale v1 overlay (if any)..."

rm -f /boot/overlay-user/max98357a-overlay.dtbo
if grep -q "max98357a-overlay" "$ARMBIAN_ENV"; then
    sed -i 's/max98357a-overlay//g; s/user_overlays=  */user_overlays=/; s/  */ /g' "$ARMBIAN_ENV"
    ok "Stale max98357a-overlay removed from $ARMBIAN_ENV"
else
    ok "No stale overlay found"
fi

# ============================================================
# STEP 2: Generate + compile the working overlay
# ============================================================
echo "==> Generating Device Tree Overlay (rock5bplus-max98357a)..."

DTS_FILE="/tmp/rock5bplus-max98357a.dts"
DTBO_FILE="/boot/overlay-user/rock5bplus-max98357a.dtbo"

cat > "$DTS_FILE" << 'DTSEOF'
// MAX98357A I2S DAC/amp on ROCK 5B+ (RK3588) — VERIFIED WORKING
// I2S2 (M1 pinmux): pin 12 BCLK, pin 35 LRC, pin 40 DIN
/dts-v1/;
/plugin/;

/ {
	compatible = "radxa,rock-5b-plus", "radxa,rock-5b", "rockchip,rk3588";

	fragment@0 {
		target-path = "/";
		__overlay__ {
			max98357a: max98357a {
				compatible = "maxim,max98357a";
				#sound-dai-cells = <0>;
			};

			sound_i2s2: i2s2-sound {
				compatible = "simple-audio-card";
				simple-audio-card,name = "Aquilla Speakers";
				simple-audio-card,format = "i2s";
				simple-audio-card,mclk-fs = <256>;

				simple-audio-card,cpu {
					sound-dai = <&i2s2_2ch>;
				};
				simple-audio-card,codec {
					sound-dai = <&max98357a>;
				};
			};
		};
	};

	fragment@1 {
		target = <&i2s2_2ch>;
		__overlay__ {
			status = "okay";
			#sound-dai-cells = <0>;
		};
	};
};
DTSEOF

command -v dtc &>/dev/null || { apt-get update -qq; apt-get install -y -qq device-tree-compiler; }
mkdir -p /boot/overlay-user
dtc -@ -I dts -O dtb -o "$DTBO_FILE" "$DTS_FILE" 2>/dev/null
ok "Compiled to $DTBO_FILE"

# Ensure user_overlays contains exactly one entry for it
if grep -q "^user_overlays=" "$ARMBIAN_ENV"; then
    if ! grep "^user_overlays=" "$ARMBIAN_ENV" | grep -q "rock5bplus-max98357a"; then
        sed -i "s|^user_overlays=\(.*\)|user_overlays=\1 rock5bplus-max98357a|; s/user_overlays=  */user_overlays=/" "$ARMBIAN_ENV"
    fi
else
    echo "user_overlays=rock5bplus-max98357a" >> "$ARMBIAN_ENV"
fi
ok "user_overlays: $(grep ^user_overlays= $ARMBIAN_ENV | cut -d= -f2)"

# ============================================================
# STEP 3: Build the snd-soc-max98357a codec module
# ============================================================
# The vendor kernel does not ship this driver. It must be compiled against
# headers that EXACTLY match the running kernel, or insmod fails with
# "disagrees about version of symbol module_layout".
echo "==> Checking codec kernel module..."

KVER="$(uname -r)"
if modinfo -n snd_soc_max98357a &>/dev/null && [ -e "/lib/modules/$KVER/extra/snd-soc-max98357a.ko" ]; then
    ok "Module already installed for $KVER"
else
    echo "    Building snd-soc-max98357a for $KVER ..."
    apt-get install -y -qq linux-headers-vendor-rk35xx build-essential wget

    if [ ! -d "/lib/modules/$KVER/build" ]; then
        fail "Headers dir /lib/modules/$KVER/build missing — kernel and headers are out of sync.
    Fix: sudo apt-get install --reinstall linux-image-vendor-rk35xx linux-headers-vendor-rk35xx
    then REBOOT and re-run this script."
    fi

    BUILD_DIR="$(mktemp -d)"
    cd "$BUILD_DIR"
    wget -q https://raw.githubusercontent.com/torvalds/linux/v6.1/sound/soc/codecs/max98357a.c \
        || fail "Could not download max98357a.c (network?)"
    printf "obj-m := snd-soc-max98357a.o\nsnd-soc-max98357a-objs := max98357a.o\n" > Makefile
    make -C "/lib/modules/$KVER/build" M="$PWD" modules
    mkdir -p "/lib/modules/$KVER/extra"
    cp snd-soc-max98357a.ko "/lib/modules/$KVER/extra/"
    depmod -a
    ok "Module built and installed"
fi

echo "snd-soc-max98357a" > /etc/modules-load.d/max98357a.conf
ok "Module auto-load configured"

# ============================================================
# STEP 4: ALSA config — DAC as default playback + USB headset mic
# ============================================================
# Card name "Aquilla Speakers" → ALSA auto-generates card ID "Speakers".
# The MAX98357A is playback-only, so the default device is `asym`:
#   playback -> Aquilla Speakers, capture -> USB headset (auto-detected).
# VERIFIED WORKING 2026-07-20 (full duplex, Plantronics USB headset mic).
# NOTE: shorthand `defaults.pcm.card <id>` lines break alsa-lib parsing
# here ("card is not a string") — use only the explicit form below.
echo "==> Configuring ALSA (playback: Aquilla Speakers, capture: USB headset)..."

[ -f /etc/asound.conf ] && cp /etc/asound.conf "/etc/asound.conf.bak.$(date +%s)"

MIC_CARD="$(arecord -l 2>/dev/null | grep -i usb | sed -n 's/^card [0-9]*: \([^ ]*\).*/\1/p' | head -1)"

if [ -n "$MIC_CARD" ]; then
    ok "USB capture card detected: $MIC_CARD (headset mic)"
    cat > /etc/asound.conf << ALSAEOF
# Aquilla audio — VERIFIED WORKING split-device config.
#   playback -> Aquilla Speakers / MAX98357A (card ID: Speakers)
#   capture  -> USB headset mic (card ID: $MIC_CARD, mic input ONLY —
#               the headset's own speakers are not referenced)
# \`plug\` handles resampling — SIP narrowband 8 kHz plays fine.

pcm.!default {
    type asym
    playback.pcm "speakers_out"
    capture.pcm "headset_in"
}
pcm.speakers_out {
    type plug
    slave.pcm "hw:Speakers,0"
}
pcm.headset_in {
    type plug
    slave.pcm "hw:$MIC_CARD,0"
}
ctl.!default {
    type hw
    card "Speakers"
}

# Back-compat alias so \`-D max98357a\` and older console selections still work
pcm.max98357a {
    type plug
    slave.pcm "hw:Speakers,0"
}
ALSAEOF
    ok "ALSA default: playback → Aquilla Speakers, capture → $MIC_CARD"
else
    warn "No USB capture card found — writing playback-only config."
    warn "Plug the headset in and RE-RUN this script to enable the mic."
    cat > /etc/asound.conf << 'ALSAEOF'
# Aquilla Speakers (MAX98357A I2S DAC) — playback-only config.
# Re-run setup-max98357a.sh with the USB headset plugged in to add capture.

pcm.!default {
    type plug
    slave.pcm "hw:Speakers,0"
}
ctl.!default {
    type hw
    card "Speakers"
}
pcm.max98357a {
    type plug
    slave.pcm "hw:Speakers,0"
}
ALSAEOF
    ok "ALSA default → Aquilla Speakers (playback only)"
fi

# ============================================================
# STEP 5: PipeWire label (if installed)
# ============================================================
if command -v pipewire &>/dev/null; then
    WPDIR="/etc/wireplumber/wireplumber.conf.d"
    mkdir -p "$WPDIR"
    cat > "$WPDIR/90-max98357a-label.conf" << 'WPEOF'
monitor.alsa.rules = [
  {
    matches = [
      { node.name = "~alsa_output.*[Ss]peakers*" }
    ]
    actions = {
      update-props = {
        node.description = "Aquilla Speakers (MAX98357A)"
      }
    }
  }
]
WPEOF
    ok "PipeWire/WirePlumber label configured"
else
    ok "PipeWire not installed — using ALSA directly"
fi

# ============================================================
# STEP 6: Clean up any forced audio-output override
# ============================================================
if grep -q "^AQUILLA_OUTPUT_DEVICE=" /etc/environment 2>/dev/null; then
    sed -i '/^AQUILLA_OUTPUT_DEVICE=/d' /etc/environment
    ok "Removed forced AQUILLA_OUTPUT_DEVICE (console selector + system default decide)"
else
    ok "No forced AQUILLA_OUTPUT_DEVICE present"
fi

# ============================================================
# DONE
# ============================================================
echo ""
echo "============================================================"
echo -e "  ${GREEN}Aquilla Speakers (MAX98357A) Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  Wiring reminder (40-pin header):"
echo "    BCLK → Pin 12    DIN  → Pin 40"
echo "    LRCK → Pin 35    VIN  → Pin 2 (5V)"
echo "    SD   → Pin 17 (3.3V) or floating on Adafruit-style boards"
echo "    GND  → Pin 6"
echo ""
echo "  Next steps:"
echo "    1. sudo reboot"
echo "    2. aplay -l          # expect: card N: Speakers [Aquilla Speakers]"
echo "    3. speaker-test -c 2 -t wav -l 1        # default device"
echo "    4. Mic loopback test (USB headset plugged in):"
echo "         arecord -f S16_LE -r 48000 -c 1 -d 4 /tmp/mictest.wav"
echo "         aplay /tmp/mictest.wav             # your voice from the speaker"
echo ""
echo "  Defaults: playback = Aquilla Speakers, capture = USB headset mic."
echo "  The Aquilla console works on 'System Default' — no selection needed."
echo "  Plugged the headset in after running this? Just re-run the script."
echo "============================================================"
