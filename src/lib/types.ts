export type CodecType = 'G.711µ' | 'G.722' | 'Opus';

export type CallStatus = 'IDLE' | 'RINGING' | 'CONNECTED' | 'FAILED' | 'INCOMING';

export interface ChannelState {
  id: number;
  label: string;
  protocol: 'SIP' | 'RTP';
  slot: string;
  targetUri: string;
  targetIp?: string;
  targetPort?: number;
  sipUser?: string;
  codec: CodecType;
  status: CallStatus;
  duration: number; // in seconds
  audioLevel: number; // 0 - 100
  latency: number; // ms
  jitter: number; // ms
  packetLoss: number; // percentage
  rxKbps: number; // kbps
  txKbps: number; // kbps
  pttActive?: boolean;
  localPort?: number;
  volume: number;
  srtpEnabled?: boolean;
  sipAuthRequired?: boolean;
  ampIp?: string;
  ampPort?: number;
  ampStreaming?: boolean;
  ampEnabled?: boolean;
  bridgeIp?: string;
  bridgePort?: number;
  bridgeEnabled?: boolean;
  /** Fixed local UDP port the ACU peer should send its RTP to. Undefined/0 = auto (ephemeral, not stable across calls). */
  bridgeLocalPort?: number;
  /** Runtime status: true while a live two-way ACU Bridge leg is up for this call. */
  bridgeConnected?: boolean;
  /** Runtime status: true while the ACU Bridge keepalive has confirmed the RTP link is live (valid RTP from the ACU Z seen within the last few seconds). Distinct from bridgeConnected. */
  bridgeLinkAlive?: boolean;
  /** Runtime status: true while this channel is actively patched into a Dispatcher group with a live call. */
  dispatchConnected?: boolean;
  /** ED-137 (EUROCAE VoIP-ATM Radio interop standard): tag outgoing RTP with the ED-137A/B/C PTT/SQU header extension for a real radio/VCS. */
  ed137Enabled?: boolean;
  /** PTT source id (0-63) this channel identifies itself as in the ED-137 extension word. */
  ed137PttId?: number;
  /** Runtime status: true while the most recently received ED-137 extension reported squelch (carrier present) from the radio. */
  ed137RemoteSquelch?: boolean;
  /** Runtime status: true while the most recently received ED-137 extension reported a keyed PTT from the far end. */
  ed137RemotePtt?: boolean;
}

export interface GlobalSettings {
  sbcIp: string;
  sipPort: string;
  isSimulatorMode: boolean;
  isConnected: boolean;
  selectedDevice: string;
  availableDevices: string[];
  localIp?: string;
  ampEnabled?: boolean;
  bridgeEnabled?: boolean;
}

export interface DispatchGroup {
  id: number;
  name: string;
  memberIds: number[];
  mirrorEnabled: boolean;
  mirrorIp: string;
  mirrorPort: number;
  mirrorLocalPort?: number;
}

export type LogLevel = 'info' | 'success' | 'warning' | 'error' | 'sip_tx' | 'sip_rx';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  channelId?: number;
  message: string;
}
