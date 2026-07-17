#!/bin/bash
# ============================================================
# MAX98357A I2S DAC Setup for Rock 5B+ (Armbian)
# ============================================================
# Self-contained script — no other files needed.
#
# Wiring (40-pin header):
#   BCLK  → Pin 12 (GPIO3_B5 / I2S2_SCLK_M1)
#   LRCK  → Pin 35 (GPIO3_B6 / I2S2_LRCK_M1)
#   DIN   → Pin 40 (GPIO3_B3 / I2S2_SDO_M1)
#   VIN   → Pin 2 or 4 (5V)
#   GND   → Pin 6, 9, 14, 20, 25, 30, 34, or 39
#   SD    → Pin 17 (3.3V) — REQUIRED or amp stays silent!
#
# Usage:
#   chmod +x setup-max98357a.sh
#   sudo ./setup-max98357a.sh
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

# Must run as root
if [ "$EUID" -ne 0 ]; then
    fail "Please run as root: sudo $0"
fi

echo ""
echo "============================================================"
echo "  MAX98357A I2S DAC Setup for Rock 5B+"
echo "============================================================"
echo ""

# ============================================================
# STEP 1: Generate the Device Tree Overlay source
# ============================================================
echo "==> Generating Device Tree Overlay..."

DTS_FILE="/tmp/max98357a-overlay.dts"
DTBO_FILE="/boot/overlay-user/max98357a-overlay.dtbo"

cat > "$DTS_FILE" << 'DTSEOF'
/dts-v1/;
/plugin/;

/ {
    compatible = "rockchip,rk3588";

    metadata {
        title = "MAX98357A I2S Audio DAC Overlay";
        compatible = "radxa,rock-5b-plus", "rockchip,rk3588";
        category = "sound";
        description = "Enable MAX98357A I2S DAC/Amp on I2S2 (m1 pins 12, 35, 40)";
    };

    /* Enable I2S2 controller with the TDM driver and route pins to 40-pin header */
    fragment@0 {
        target = <&i2s2_2ch>;
        __overlay__ {
            compatible = "rockchip,rk3588-i2s-tdm";
            status = "okay";
            #sound-dai-cells = <0>;
            /* Clock IDs from rockchip,rk3588-cru.h: MCLK_I2S2_2CH=31, HCLK_I2S2_2CH=26 */
            clocks = <&cru 31>, <&cru 31>, <&cru 26>;
            clock-names = "mclk_tx", "mclk_rx", "hclk";
            /* CLK_I2S2_2CH_SRC=28, PLL_AUPLL=4 */
            assigned-clocks = <&cru 28>;
            assigned-clock-parents = <&cru 4>;
            rockchip,clk-trcm = <1>;
            pinctrl-names = "default";
            pinctrl-0 = <&i2s2m1_lrck &i2s2m1_sclk &i2s2m1_sdi &i2s2m1_sdo>;
        };
    };

    /* Create the dummy codec (vendor kernel lacks snd-soc-max98357a module) */
    /* and the virtual sound card linking CPU DAI to Codec */
    fragment@1 {
        target-path = "/";
        __overlay__ {
            max98357a_codec: max98357a-codec {
                #sound-dai-cells = <0>;
                compatible = "linux,spdif-dit";
                status = "okay";
            };

            max98357a_sound: max98357a-sound {
                compatible = "simple-audio-card";
                simple-audio-card,name = "MAX98357A";
                simple-audio-card,format = "i2s";

                /* Rock 5B+ is the I2S clock master */
                simple-audio-card,bitclock-master = <&cpu_dai>;
                simple-audio-card,frame-master = <&cpu_dai>;
                simple-audio-card,mclk-fs = <256>;

                cpu_dai: simple-audio-card,cpu {
                    sound-dai = <&i2s2_2ch>;
                };

                simple-audio-card,codec {
                    sound-dai = <&max98357a_codec>;
                };
            };
        };
    };

    /* Disable the conflicting sound-max98357a node from the base device tree */
    fragment@2 {
        target-path = "/sound-max98357a";
        __overlay__ {
            status = "disabled";
        };
    };
};
DTSEOF

ok "DTS source generated"

# ============================================================
# STEP 2: Compile the overlay
# ============================================================
echo "==> Compiling Device Tree Overlay..."

mkdir -p /boot/overlay-user

if ! command -v dtc &>/dev/null; then
    echo "    Installing device-tree-compiler..."
    apt-get update -qq
    apt-get install -y -qq device-tree-compiler
fi

dtc -@ -I dts -O dtb -o "$DTBO_FILE" "$DTS_FILE" 2>/dev/null
ok "Compiled to $DTBO_FILE"

# ============================================================
# STEP 3: Enable overlay in Armbian boot config
# ============================================================
echo "==> Configuring boot loader..."

ARMBIAN_ENV="/boot/armbianEnv.txt"

if [ ! -f "$ARMBIAN_ENV" ]; then
    fail "$ARMBIAN_ENV not found — is this Armbian?"
fi

# Ensure user_overlays line includes our overlay
if grep -q "^user_overlays=" "$ARMBIAN_ENV"; then
    CURRENT=$(grep "^user_overlays=" "$ARMBIAN_ENV" | cut -d= -f2)
    if echo "$CURRENT" | grep -q "max98357a-overlay"; then
        ok "Overlay already listed in $ARMBIAN_ENV"
    else
        sed -i "s|^user_overlays=.*|user_overlays=${CURRENT} max98357a-overlay|" "$ARMBIAN_ENV"
        ok "Appended overlay to existing user_overlays"
    fi
else
    echo "user_overlays=max98357a-overlay" >> "$ARMBIAN_ENV"
    ok "Added user_overlays=max98357a-overlay"
fi

# ============================================================
# STEP 4: Load required kernel modules
# ============================================================
echo "==> Configuring kernel modules..."

# Ensure the I2S TDM module loads at boot
MODULES_FILE="/etc/modules-load.d/audio-i2s.conf"
cat > "$MODULES_FILE" << 'MODEOF'
# I2S audio support for MAX98357A DAC
snd-soc-rockchip-i2s-tdm
snd-soc-simple-card
snd-soc-spdif-tx
MODEOF

ok "Module auto-load configured"

# Try to load now (may fail if already loaded, that's OK)
modprobe snd-soc-rockchip-i2s-tdm 2>/dev/null || true
modprobe snd-soc-simple-card 2>/dev/null || true
modprobe snd-soc-spdif-tx 2>/dev/null || true

# ============================================================
# STEP 5: Expose the DAC as a selectable ALSA device
# ============================================================
# NOTE: The DAC is now OPT-IN. We make the card available (and a handy
# `max98357a` alias for speaker-test), but we DO NOT override the system
# `!default`. Onboard/HDMI audio stays the OS default, and the Aquilla
# console's "Audio Output Interface" selector routes playback to the DAC
# only when the operator explicitly picks it.
echo "==> Configuring ALSA (DAC as a selectable device, not forced default)..."

ASOUND_CONF="/etc/asound.conf"

# If a previous install forced MAX98357A as the global default, remove that
# override so the console selector is authoritative again.
if [ -f "$ASOUND_CONF" ] && grep -q "MAX98357A" "$ASOUND_CONF"; then
    cp "$ASOUND_CONF" "${ASOUND_CONF}.bak.$(date +%s)" 2>/dev/null || true
    warn "Existing $ASOUND_CONF backed up; replacing forced-default config"
fi

cat > "$ASOUND_CONF" << 'ALSAEOF'
# MAX98357A I2S DAC — exposed as a named device only.
# The system default is intentionally left untouched so onboard audio
# remains the default. Select "MAX98357A" in the Aquilla console to route
# call audio to the DAC. Use `-D max98357a` for direct testing.

pcm.max98357a {
    type plug
    slave {
        pcm {
            type hw
            card "MAX98357A"
            device 0
        }
        rate 48000
        channels 2
        format S16_LE
    }
}
ALSAEOF

ok "ALSA configured — MAX98357A available as a named device (system default unchanged)"

# ============================================================
# STEP 6: Configure PipeWire (if installed)
# ============================================================
echo "==> Checking PipeWire..."

if command -v pipewire &>/dev/null; then
    WPDIR="/etc/wireplumber/wireplumber.conf.d"

    # OPT-IN: remove any prior rule that forced MAX98357A to be the default
    # sink, so onboard audio stays default and the console selector decides
    # routing. We only give the node a friendly description — no priority bump.
    OLD_RULE="$WPDIR/90-max98357a-default.conf"
    if [ -f "$OLD_RULE" ]; then
        rm -f "$OLD_RULE"
        warn "Removed previous WirePlumber default-sink rule (DAC no longer forced)"
    fi

    mkdir -p "$WPDIR"
    cat > "$WPDIR/90-max98357a-label.conf" << 'WPEOF'
monitor.alsa.rules = [
  {
    matches = [
      { node.name = "~alsa_output.*max98357a*" }
      { node.name = "~alsa_output.*MAX98357A*" }
    ]
    actions = {
      update-props = {
        node.description = "Aquilla Speaker (MAX98357A)"
      }
    }
  }
]
WPEOF

    ok "PipeWire/WirePlumber configured — MAX98357A labelled, NOT forced as default"
else
    ok "PipeWire not installed — using ALSA directly"
fi

# ============================================================
# STEP 7: Clean up any forced audio-output override
# ============================================================
# AQUILLA_OUTPUT_DEVICE is now an OPTIONAL hard override that outranks the
# console selector. A fresh DAC install should NOT set it — leaving it unset
# lets the operator choose the output in the Aquilla console. Here we remove
# any value a previous install baked into /etc/environment so the selector
# takes effect. (To force the DAC regardless of the console — e.g. an
# appliance build — set AQUILLA_OUTPUT_DEVICE=MAX98357A yourself.)
echo "==> Ensuring audio output is console-selectable (not env-forced)..."

ENV_FILE="/etc/environment"
if grep -q "^AQUILLA_OUTPUT_DEVICE=" "$ENV_FILE" 2>/dev/null; then
    sed -i '/^AQUILLA_OUTPUT_DEVICE=/d' "$ENV_FILE"
    ok "Removed forced AQUILLA_OUTPUT_DEVICE from $ENV_FILE (console now decides output)"
else
    ok "No forced AQUILLA_OUTPUT_DEVICE present — output is console-selectable"
fi

# ============================================================
# DONE
# ============================================================
echo ""
echo "============================================================"
echo -e "  ${GREEN}MAX98357A Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "  Wiring reminder (40-pin header):"
echo "    BCLK → Pin 12    DIN  → Pin 40"
echo "    LRCK → Pin 35    VIN  → Pin 2 (5V)"
echo -e "    ${YELLOW}SD   → Pin 17 (3.3V) ← REQUIRED!${NC}"
echo "    GND  → Pin 6"
echo ""
echo "  Next steps:"
echo "    1. Verify SD pin is wired to 3.3V (Pin 17)"
echo "    2. Reboot:  sudo reboot"
echo "    3. Test the DAC directly:"
echo "         speaker-test -c 2 -r 48000 -D max98357a -t sine"
echo -e "    4. ${YELLOW}In the Aquilla console → Settings → Audio Output Interface,"
echo -e "       select \"MAX98357A\" to route call audio to the DAC.${NC}"
echo "       (Leaving it \"System Default (SBC onboard)\" uses onboard audio.)"
echo ""
echo "============================================================"
