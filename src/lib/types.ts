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
}

export type LogLevel = 'info' | 'success' | 'warning' | 'error' | 'sip_tx' | 'sip_rx';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  channelId?: number;
  message: string;
}
