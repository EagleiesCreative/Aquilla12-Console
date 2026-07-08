//! EUROCAE ED-137 (VoIP interoperability standard for ATM — "Radio", Part 1)
//! RTP header extension codec.
//!
//! This implements the RTP header extension carrying PTT (push-to-talk) and
//! SQU (squelch) signalling used by ED-137 / ED-137A / ED-137B / ED-137C
//! compliant radio/VCS equipment, so this console can key/receive real radio
//! hardware over IP instead of plain unsignalled RTP/PCMU.
//!
//! Layout follows the generic RTP header extension mechanism (RFC 3550
//! §5.3.1): a 4-byte generic header (16-bit "defined by profile" id + 16-bit
//! length in 32-bit words) followed by `length * 4` bytes of extension data.
//!
//! Two wire formats exist:
//!   - ED-137 (first edition): id = 0x0067, one 32-bit fixed-format word.
//!   - ED-137A/B/C:             id = 0x0167, one 16-bit fixed-format word
//!                               (padded to a full 32-bit word on the wire).
//! ED-137A/B/C is what current-generation VCS/radio gateways implement, so
//! that is what this console transmits; both are decoded on receive.
//!
//! Bit layout cross-checked against Wireshark's `packet-rtp-ed137.c`
//! dissector (EUROCAE-conformant, field-for-field with the standard).

/// "Defined by profile" id for the original ED-137 32-bit extension word.
pub const ED137_SIG: u16 = 0x0067;
/// "Defined by profile" id for the ED-137A/B/C 16-bit extension word.
pub const ED137B_SIG: u16 = 0x0167;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PttType {
    Off = 0,
    Normal = 1,
    Coupling = 2,
    Priority = 3,
    Emergency = 4,
    Test = 5,
}

impl PttType {
    pub fn from_bits(bits: u8) -> PttType {
        match bits & 0x07 {
            1 => PttType::Normal,
            2 => PttType::Coupling,
            3 => PttType::Priority,
            4 => PttType::Emergency,
            5 => PttType::Test,
            _ => PttType::Off,
        }
    }

    pub fn is_keyed(self) -> bool {
        !matches!(self, PttType::Off)
    }
}

/// Decoded (or to-be-encoded) fixed-header fields of an ED-137 RTP extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed137Fields {
    pub ptt_type: PttType,
    /// Squelch: true while the radio reports carrier/signal present (downlink).
    pub squ: bool,
    /// PTT source id (radio port / operator identifier), 6 bits (0-63) in the
    /// ED-137A/B/C word.
    pub ptt_id: u8,
    /// PTT Mute (ED-137A/B/C only).
    pub ptt_mute: bool,
    /// PTT Summation (ED-137A/B/C only).
    pub ptt_summation: bool,
    /// Simultaneous Call Transmissions.
    pub sct: bool,
}

impl Default for Ed137Fields {
    fn default() -> Self {
        Ed137Fields {
            ptt_type: PttType::Off,
            squ: false,
            ptt_id: 0,
            ptt_mute: false,
            ptt_summation: false,
            sct: false,
        }
    }
}

/// Encode the ED-137A/B/C (16-bit word) RTP header extension: returns the
/// full 8 bytes to splice in right after the fixed 12-byte RTP header (and
/// after any CSRC list), i.e. `[id(2), length=1(2), word(2), reserved(2)]`.
pub fn encode_ed137b(fields: &Ed137Fields) -> [u8; 8] {
    let mut word: u16 = 0;
    word |= ((fields.ptt_type as u16) & 0x07) << 13;
    word |= (fields.squ as u16) << 12;
    word |= ((fields.ptt_id as u16) & 0x3F) << 6;
    word |= (fields.ptt_mute as u16) << 5;
    word |= (fields.ptt_summation as u16) << 4;
    word |= (fields.sct as u16) << 3;
    // bits 2-1 reserved, bit 0 (X) = 0: no additional feature blocks used.

    let mut out = [0u8; 8];
    out[0] = (ED137B_SIG >> 8) as u8;
    out[1] = (ED137B_SIG & 0xFF) as u8;
    out[2] = 0x00;
    out[3] = 0x01; // length = 1 (32-bit word)
    out[4] = (word >> 8) as u8;
    out[5] = (word & 0xFF) as u8;
    out[6] = 0x00;
    out[7] = 0x00; // reserved padding to fill the 32-bit word
    out
}

fn decode_word_b(word: u16) -> Ed137Fields {
    Ed137Fields {
        ptt_type: PttType::from_bits(((word & 0xE000) >> 13) as u8),
        squ: (word & 0x1000) != 0,
        ptt_id: ((word & 0x0FC0) >> 6) as u8,
        ptt_mute: (word & 0x0020) != 0,
        ptt_summation: (word & 0x0010) != 0,
        sct: (word & 0x0008) != 0,
    }
}

fn decode_word_orig(word: u32) -> Ed137Fields {
    Ed137Fields {
        ptt_type: PttType::from_bits(((word & 0xE000_0000) >> 29) as u8),
        squ: (word & 0x1000_0000) != 0,
        ptt_id: ((word & 0x0F00_0000) >> 24) as u8,
        ptt_mute: false,
        ptt_summation: false,
        sct: (word & 0x0080_0000) != 0,
    }
}

/// Compute the total RTP fixed-header length in bytes (12-byte base header +
/// CSRC list + generic extension header/data, if the extension bit is set).
/// Returns `None` if `data` is too short to be a valid RTP packet or claims
/// an extension longer than the buffer actually holds.
pub fn rtp_header_len(data: &[u8]) -> Option<usize> {
    if data.len() < 12 {
        return None;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return None;
    }
    let cc = (data[0] & 0x0F) as usize;
    let has_extension = ((data[0] >> 4) & 0x01) == 1;

    let mut header_len = 12 + cc * 4;
    if has_extension {
        if data.len() < header_len + 4 {
            return None;
        }
        let ext_len_words = ((data[header_len + 2] as usize) << 8) | (data[header_len + 3] as usize);
        header_len += 4 + ext_len_words * 4;
    }

    if data.len() < header_len {
        return None;
    }
    Some(header_len)
}

/// Locate and decode an ED-137 (any edition) RTP header extension in a raw
/// RTP packet, if present. Returns `None` if there is no extension, the
/// extension isn't an ED-137 one (unrecognised "defined by profile" id), or
/// the packet is malformed.
pub fn parse_rtp_ed137(data: &[u8]) -> Option<Ed137Fields> {
    if data.len() < 12 {
        return None;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return None;
    }
    let cc = (data[0] & 0x0F) as usize;
    let has_extension = ((data[0] >> 4) & 0x01) == 1;
    if !has_extension {
        return None;
    }

    let ext_hdr_offset = 12 + cc * 4;
    if data.len() < ext_hdr_offset + 4 {
        return None;
    }
    let sig = ((data[ext_hdr_offset] as u16) << 8) | (data[ext_hdr_offset + 1] as u16);
    let len_words = ((data[ext_hdr_offset + 2] as usize) << 8) | (data[ext_hdr_offset + 3] as usize);
    let ext_data_offset = ext_hdr_offset + 4;
    let ext_data_len = len_words * 4;
    if data.len() < ext_data_offset + ext_data_len {
        return None;
    }

    match sig {
        ED137B_SIG => {
            if ext_data_len < 2 {
                return None;
            }
            let word = ((data[ext_data_offset] as u16) << 8) | (data[ext_data_offset + 1] as u16);
            Some(decode_word_b(word))
        }
        ED137_SIG => {
            if ext_data_len < 4 {
                return None;
            }
            let word = ((data[ext_data_offset] as u32) << 24)
                | ((data[ext_data_offset + 1] as u32) << 16)
                | ((data[ext_data_offset + 2] as u32) << 8)
                | (data[ext_data_offset + 3] as u32);
            Some(decode_word_orig(word))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_normal_ptt() {
        let fields = Ed137Fields {
            ptt_type: PttType::Normal,
            squ: false,
            ptt_id: 7,
            ptt_mute: false,
            ptt_summation: false,
            sct: false,
        };
        let ext = encode_ed137b(&fields);

        // Build a minimal RTP packet: 12-byte header (X bit set, cc=0) + ext + no payload.
        let mut packet = vec![0u8; 12];
        packet[0] = 0x90; // version 2, extension bit set
        packet.extend_from_slice(&ext);

        let decoded = parse_rtp_ed137(&packet).expect("should decode");
        assert_eq!(decoded.ptt_type, PttType::Normal);
        assert_eq!(decoded.ptt_id, 7);
        assert!(!decoded.squ);
    }

    #[test]
    fn decodes_squelch_from_radio() {
        let fields = Ed137Fields {
            ptt_type: PttType::Off,
            squ: true,
            ptt_id: 3,
            ptt_mute: false,
            ptt_summation: false,
            sct: false,
        };
        let ext = encode_ed137b(&fields);
        let mut packet = vec![0u8; 12];
        packet[0] = 0x90;
        packet.extend_from_slice(&ext);

        let decoded = parse_rtp_ed137(&packet).unwrap();
        assert!(decoded.squ);
        assert_eq!(decoded.ptt_type, PttType::Off);
    }

    #[test]
    fn header_len_accounts_for_extension() {
        let fields = Ed137Fields::default();
        let ext = encode_ed137b(&fields);
        let mut packet = vec![0u8; 12];
        packet[0] = 0x90;
        packet.extend_from_slice(&ext);
        packet.extend_from_slice(&[0xFFu8; 160]); // payload

        assert_eq!(rtp_header_len(&packet), Some(12 + 8));
    }

    #[test]
    fn no_extension_returns_none() {
        let mut packet = vec![0u8; 12 + 160];
        packet[0] = 0x80;
        assert_eq!(parse_rtp_ed137(&packet), None);
        assert_eq!(rtp_header_len(&packet), Some(12));
    }
}
