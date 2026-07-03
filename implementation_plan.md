# Simplify AudioLimiter & Fix AGC / Peaking

The current audio processing pipeline in `lib.rs` (V3) is over-processing the audio. The adaptive noise reduction, noise gate, bandpass filters, AGC, and peak limiter are fighting each other. This results in gain pumping, cut-off speech, and severe crackling/clipping when the AGC overshoots or the limiter's fast-attack fails to catch sudden transients cleanly.

This plan details a simplified, professional audio processing chain that resolves these issues:
1. **Remove** Wiener noise reduction, bandpass filters, and noise gate.
2. **Add** a simple 1st-order High-Pass Filter (DC Block + rumble removal) at 120Hz.
3. **Implement a professional AGC**:
   - Slow envelope follower tracking peak audio levels (10ms attack, 500ms release).
   - **Silence hold/freeze**: freezes/decays gain to unity during silence (below 200.0 peak) to prevent noise floor amplification and initial-syllable clipping.
   - Smooth sample-by-sample gain interpolation with fast-attack (15ms) and extremely slow-release (2.0s) to keep volume stable without pumping.
4. **Implement a Zero-Latency Soft-Knee Limiter**:
   - Applies smooth continuous exponential saturation above 16000.0 up to a hard ceiling of 26000.0.
   - Prevents hard clipping or crackling by rounding off peaks gracefully rather than letting them hit the brick wall.

---

## Proposed Changes


### Rust Backend (Tauri)

#### [MODIFY] [lib.rs](file:///Users/christinaindahsetiyorini/Documents/Eagleies%20Creative/SIP%20Controller/src-tauri/src/lib.rs)

We will rewrite `AudioLimiter` and its `process` method to follow this new design:

```rust
struct AudioLimiter {
    // --- High-Pass Filter (120Hz cutoff at 8kHz) ---
    hp_a: f64,
    hp_prev_in: f64,
    hp_prev_out: f64,

    // --- AGC Peak Envelope Follower ---
    envelope: f64,
    env_attack: f64,
    env_release: f64,

    // --- AGC Gain Control ---
    target_volume: f64,
    max_gain: f64,
    current_gain: f64,
    gain_attack: f64,
    gain_release: f64,
}
```

Its implementation will:
1. Initialize constants dynamically based on sample rate (8000 Hz).
2. Filter the signal with a 120Hz HPF to remove low-frequency rumble.
3. Update the envelope of the signal.
4. If envelope > 200.0, calculate `target_gain = target_volume / envelope` (clamped between 0.5 and `max_gain`). Otherwise, set `target_gain = 1.0`.
5. Interpolate `current_gain` sample-by-sample.
6. Apply `current_gain`.
7. If the sample exceeds 16000.0, apply a soft-knee saturation curve capping at 26000.0.
8. Output the clamped value.

---

## Verification Plan

### Automated Tests
- Run `cargo check` to ensure the simplified code compiles cleanly.

### Manual Verification
1. Place a SIP call.
2. Verify that there is no more crackling or peaking when speech starts or during loud sounds.
3. Verify that the AGC holds gain during silence and adjusts smoothly without pumping.
4. Verify that the voice sounds natural and clear (without aggressive suppression/bandpass artifacts).
