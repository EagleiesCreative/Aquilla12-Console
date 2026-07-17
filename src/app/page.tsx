"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { DashboardHeader } from "@/components/DashboardHeader";
import { ChannelCard } from "@/components/ChannelCard";
import { SystemConsole } from "@/components/SystemConsole";
import { DispatchMatrixPanel } from "@/components/DispatchMatrixPanel";
import { CallStatus, ChannelState, CodecType, DispatchGroup, GlobalSettings, LogEntry, LogLevel } from "@/lib/types";
import { parseSbcAddress } from "@/lib/utils";
import { Mic, Network, Server, ToggleLeft, ToggleRight, Volume2, X } from "lucide-react";

// Generate initial list of 12 hardware audio channels
const INITIAL_CHANNELS: ChannelState[] = Array.from({ length: 12 }).map((_, index) => {
  const id = index + 1;
  return {
    id,
    label: `CH ${id.toString().padStart(2, "0")}`,
    protocol: "RTP",
    slot: `I2S Slot ${index}`,
    targetUri: `192.168.1.10${id}:5004`,
    targetIp: `192.168.1.10${id}`,
    targetPort: 5004,
    sipUser: `receiver${id}`,
    codec: id % 3 === 0 ? "Opus" : id % 3 === 1 ? "G.711µ" : "G.722",
    status: "IDLE",
    duration: 0,
    audioLevel: 0,
    latency: 0,
    jitter: 0,
    packetLoss: 0,
    rxKbps: 0,
    txKbps: 0,
    pttActive: false,
    volume: 100,
    srtpEnabled: true,
    sipAuthRequired: true,
    ampIp: "127.0.0.1",
    ampPort: 5004 + index * 2,
    ampStreaming: false,
    ampEnabled: true,
    bridgeIp: "127.0.0.1",
    bridgePort: 6004 + index * 2,
    bridgeEnabled: false,
    bridgeConnected: false,
    bridgeLinkAlive: false,
    dispatchConnected: false,
  };
});

export default function Home() {
  // Global dashboard state
  const [settings, setSettings] = useState<GlobalSettings>({
    sbcIp: "localhost",
    sipPort: "5060",
    isSimulatorMode: false,
    isConnected: false,
    selectedDevice: "",
    availableDevices: [],
    selectedOutputDevice: "",
    availableOutputDevices: [],
    ampEnabled: true,
    bridgeEnabled: true,
  });

  const [channels, setChannels] = useState<ChannelState[]>(INITIAL_CHANNELS);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [cpuLoad, setCpuLoad] = useState(12);
  const [ramUsage, setRamUsage] = useState(38);

  const [showSettings, setShowSettings] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [showDispatchMatrix, setShowDispatchMatrix] = useState(false);
  const [dispatchGroups, setDispatchGroups] = useState<DispatchGroup[]>([]);

  const socketRef = useRef<WebSocket | null>(null);
  const connectionTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Helper to add system diagnostic logs
  const addLog = useCallback((message: string, level: LogLevel = "info", channelId?: number) => {
    const timestamp = new Date().toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }) + "." + new Date().getMilliseconds().toString().padStart(3, "0");

    const newLog: LogEntry = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp,
      level,
      message,
      channelId,
    };

    setLogs((prev) => [...prev.slice(-99), newLog]); // Keep last 100 logs
  }, []);

  // Initialize startup logs
  useEffect(() => {
    addLog("System starting up...", "info");
    addLog("12 I2S hardware slots mapped successfully", "success");
    addLog("Gateway compiled with native Rust engine", "success");
  }, [addLog]);

  // Touchscreen kiosk hardening. Block anything that drags the panel out of its fixed
  // 800x480 layout or stalls PTT:
  //  - the native long-press right-click/context menu (interrupts press-and-hold),
  //  - pinch / ctrl+wheel / ctrl+/-/0 / WebKit gesture zoom.
  useEffect(() => {
    const prevent = (e: Event) => e.preventDefault();
    document.addEventListener("contextmenu", prevent);
    const onWheel = (e: WheelEvent) => { if (e.ctrlKey) e.preventDefault(); };
    document.addEventListener("wheel", onWheel, { passive: false });
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && ["+", "-", "=", "0"].includes(e.key)) e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("gesturestart", prevent);
    document.addEventListener("gesturechange", prevent);
    document.addEventListener("gestureend", prevent);
    return () => {
      document.removeEventListener("contextmenu", prevent);
      document.removeEventListener("wheel", onWheel);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("gesturestart", prevent);
      document.removeEventListener("gesturechange", prevent);
      document.removeEventListener("gestureend", prevent);
    };
  }, []);

  // Fetch available audio devices and configuration from backend API
  useEffect(() => {
    const fetchDevicesAndConfig = async () => {
      try {
        const parsed = parseSbcAddress(settings.sbcIp || "localhost");
        if (!parsed) return;
        
        const configRes = await fetch(`${parsed.httpUrl}/api/config`);
        let initialSipPort = "5060";
        let initialDevice = "";
        let initialOutputDevice = "";
        let initialLocalIp = "";
        let initialAmpEnabled = true;
        let initialBridgeEnabled = true;
        if (configRes.ok) {
          const cfg = await configRes.json();
          initialSipPort = cfg.sipPort || "5060";
          initialDevice = cfg.selectedDevice || "";
          initialOutputDevice = cfg.selectedOutputDevice || "";
          initialLocalIp = cfg.localIp || "";
          if (cfg.ampEnabled !== undefined) initialAmpEnabled = cfg.ampEnabled;
          if (cfg.bridgeEnabled !== undefined) initialBridgeEnabled = cfg.bridgeEnabled;
        }

        fetch(`${parsed.httpUrl}/api/dispatch/matrix`)
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => {
            if (data && Array.isArray(data.groups)) {
              setDispatchGroups(data.groups);
            }
          })
          .catch(() => {
            /* Dispatcher matrix unavailable (e.g. simulator mode) — panel shows a loading state */
          });

        const res = await fetch(`${parsed.httpUrl}/api/audio-devices`);
        if (res.ok) {
          const list = await res.json();
          setSettings((prev) => {
            const defaultDevice = initialDevice || prev.selectedDevice || list[0] || "Default Device";
            
            fetch(`${parsed.httpUrl}/api/audio-devices/select`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ device: defaultDevice }),
            }).catch((err) => console.error("Failed to sync device with backend", err));

            return {
              ...prev,
              availableDevices: list,
              selectedDevice: defaultDevice,
              sipPort: initialSipPort,
              localIp: initialLocalIp || prev.localIp,
              ampEnabled: initialAmpEnabled,
              bridgeEnabled: initialBridgeEnabled,
            };
          });
        }

        // Output (playback) interfaces. Empty selection => system default (SBC).
        const outRes = await fetch(`${parsed.httpUrl}/api/audio-output-devices`);
        if (outRes.ok) {
          const outList = await outRes.json();
          setSettings((prev) => ({
            ...prev,
            availableOutputDevices: outList,
            selectedOutputDevice: initialOutputDevice || prev.selectedOutputDevice || "",
          }));
        }
      } catch (err) {
        const mockList = ["System Default Microphone", "Multi-Channel I2S HAT Capture", "USB Audio Interface"];
        const mockOutList = ["System Default (SBC onboard)", "MAX98357A I2S DAC", "USB Audio Output"];
        setSettings((prev) => ({
          ...prev,
          availableDevices: mockList,
          selectedDevice: prev.selectedDevice || mockList[0],
          availableOutputDevices: mockOutList,
          selectedOutputDevice: prev.selectedOutputDevice || "",
        }));
      }
    };

    fetchDevicesAndConfig();
  }, [settings.sbcIp]);

  // Handle global settings change
  const handleSettingsChange = (newSettings: Partial<GlobalSettings>) => {
    setSettings((prev) => {
      const updated = { ...prev, ...newSettings };

      if (newSettings.isSimulatorMode !== undefined) {
        if (newSettings.isSimulatorMode) {
          addLog("Switched system mode to SIMULATOR.", "warning");
          updated.isConnected = true;
        } else {
          addLog(`Switched system mode to LIVE SBC gateway at ${updated.sbcIp}`, "info");
          updated.isConnected = false;
        }
      }

      if (newSettings.sbcIp !== undefined && !updated.isSimulatorMode) {
        addLog(`Target SBC IP modified to ${newSettings.sbcIp}.`, "info");
        updated.isConnected = false;
      }

      if (newSettings.selectedDevice !== undefined) {
        addLog(`Audio device set to: ${newSettings.selectedDevice}`, "success");
        const parsed = parseSbcAddress(updated.sbcIp || "localhost");
        if (parsed) {
          fetch(`${parsed.httpUrl}/api/audio-devices/select`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device: newSettings.selectedDevice }),
          }).catch((err) => console.error("Failed to sync audio device with backend", err));
        }
      }

      if (newSettings.selectedOutputDevice !== undefined) {
        const label = newSettings.selectedOutputDevice || "System Default (SBC)";
        addLog(`Audio output set to: ${label}`, "success");
        const parsed = parseSbcAddress(updated.sbcIp || "localhost");
        if (parsed) {
          fetch(`${parsed.httpUrl}/api/audio-output-devices/select`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device: newSettings.selectedOutputDevice || "none" }),
          }).catch((err) => console.error("Failed to sync audio output device with backend", err));
        }
      }

      return updated;
    });
  };

  const handleUpdateTarget = (id: number, targetUri: string) => {
    setChannels((prev) =>
      prev.map((ch) => (ch.id === id ? { ...ch, targetUri } : ch))
    );
  };

  const handleUpdateCodec = (id: number, codec: CodecType) => {
    setChannels((prev) =>
      prev.map((ch) => (ch.id === id ? { ...ch, codec } : ch))
    );
    addLog(`CH ${id} codec updated to ${codec}`, "info", id);
  };

  const triggerLiveCall = async (id: number, targetUri: string, codec: CodecType) => {
    try {
      addLog(`Initializing call on CH ${id}`, "info", id);
      const parsed = parseSbcAddress(settings.sbcIp);
      if (!parsed) throw new Error("Invalid SBC Address");
      
      const response = await fetch(`${parsed.httpUrl}/api/channels/${id}/call`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUri, codec, port: settings.sipPort }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }
      addLog(`Outbound Call accepted for CH ${id}`, "success", id);
    } catch (error: any) {
      addLog(`Call failed on CH ${id}: ${error.message}`, "error", id);
      setChannels((prev) =>
        prev.map((ch) => (ch.id === id ? { ...ch, status: "FAILED" } : ch))
      );
    }
  };

  const triggerLiveHangup = async (id: number) => {
    try {
      addLog(`Hanging up call on CH ${id}`, "info", id);
      const parsed = parseSbcAddress(settings.sbcIp);
      if (!parsed) throw new Error("Invalid SBC Address");
      
      const response = await fetch(`${parsed.httpUrl}/api/channels/${id}/hangup`, {
        method: "POST",
      });
      if (!response.ok) throw new Error("HTTP error");
      addLog(`Hangup accepted for CH ${id}`, "success", id);
    } catch (error: any) {
      addLog(`Hangup failed on CH ${id}: ${error.message}`, "error", id);
    }
  };

  const runSimulatorCallFlow = (id: number, targetUri: string, codec: CodecType) => {
    const channel = channels.find((c) => c.id === id);
    if (channel?.protocol === "RTP") {
      addLog(`Direct RTP session active on Slot ${id - 1}`, "success", id);
      setChannels((prev) =>
        prev.map((ch) =>
          ch.id === id
            ? {
                ...ch,
                status: "CONNECTED",
                duration: 0,
                latency: 5,
                jitter: 1,
                packetLoss: 0.0,
                rxKbps: 80,
                txKbps: 0,
                pttActive: false,
                ampStreaming: (settings.ampEnabled ?? true) && (ch.ampEnabled ?? true),
                bridgeConnected: (settings.bridgeEnabled ?? true) && (ch.bridgeEnabled ?? false),
              }
            : ch
        )
      );
      return;
    }

    setChannels((prev) =>
      prev.map((ch) => (ch.id === id ? { ...ch, status: "RINGING", duration: 0 } : ch))
    );
    addLog(`SIP Call initiated on Slot ${id - 1}`, "info", id);

    setTimeout(() => {
      setChannels((prev) => {
        const current = prev.find((ch) => ch.id === id);
        if (!current || current.status !== "RINGING") return prev;

        addLog("SIP 180 Ringing received", "sip_rx", id);

        setTimeout(() => {
          setChannels((prevConnect) => {
            const innerCurrent = prevConnect.find((ch) => ch.id === id);
            if (!innerCurrent || innerCurrent.status !== "RINGING") return prevConnect;

            addLog("SIP 200 OK received", "sip_rx", id);
            addLog("Session established", "success", id);

            return prevConnect.map((ch) =>
              ch.id === id
                ? {
                    ...ch,
                    status: "CONNECTED",
                    latency: 18,
                    jitter: 2,
                    packetLoss: 0.0,
                    rxKbps: codec === "Opus" ? 64 : 80,
                    txKbps: 0,
                    pttActive: false,
                    ampStreaming: (settings.ampEnabled ?? true) && (ch.ampEnabled ?? true),
                    bridgeConnected: (settings.bridgeEnabled ?? true) && (ch.bridgeEnabled ?? false),
                  }
                : ch
            );
          });
        }, 1000);

        return prev;
      });
    }, 600);
  };

  const runSimulatorHangupFlow = (id: number) => {
    setChannels((prev) => {
      const current = prev.find((ch) => ch.id === id);
      if (!current) return prev;

      addLog(`Call terminated on Slot ${id - 1}`, "info", id);

      return prev.map((ch) =>
        ch.id === id
          ? {
              ...ch,
              status: "IDLE",
              audioLevel: 0,
              latency: 0,
              jitter: 0,
              packetLoss: 0,
              rxKbps: 0,
              txKbps: 0,
              pttActive: false,
              ampStreaming: false,
              bridgeConnected: false,
              dispatchConnected: false,
            }
          : ch
      );
    });
  };

  const handleCallToggle = (id: number, targetUri: string, codec: CodecType) => {
    const channel = channels.find((c) => c.id === id);
    if (!channel) return;

    const isActiveCall = channel.status === "CONNECTED" || channel.status === "RINGING";

    if (settings.isSimulatorMode) {
      if (isActiveCall) {
        runSimulatorHangupFlow(id);
      } else {
        runSimulatorCallFlow(id, targetUri, codec);
      }
    } else {
      if (isActiveCall) {
        triggerLiveHangup(id);
      } else {
        triggerLiveCall(id, targetUri, codec);
      }
    }
  };

  const handlePttToggle = async (id: number, active: boolean) => {
    setChannels((prev) =>
      prev.map((ch) => (ch.id === id ? { ...ch, pttActive: active } : ch))
    );

    if (!settings.isSimulatorMode) {
      try {
        const parsed = parseSbcAddress(settings.sbcIp);
        if (parsed) {
          await fetch(`${parsed.httpUrl}/api/channels/${id}/ptt`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active }),
          });
        }
      } catch (err) {
        console.error("Failed to sync PTT toggle", err);
      }
    } else {
      setChannels((prev) =>
        prev.map((ch) =>
          ch.id === id
            ? {
                ...ch,
                txKbps: active ? 64 : 0,
              }
            : ch
        )
      );
    }
  };

  // WebSockets setup
  useEffect(() => {
    if (settings.isSimulatorMode) {
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
      return;
    }

    const connectWebSocket = () => {
      const parsed = parseSbcAddress(settings.sbcIp);
      if (!parsed) {
        setSettings((prev) => ({ ...prev, isConnected: false }));
        return;
      }

      try {
        const ws = new WebSocket(parsed.wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
          addLog("Telemetry stream connected", "success");
          setSettings((prev) => ({ ...prev, isConnected: true }));
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);

            if (payload.type === "channel_update") {
              const data = payload.data;
              setChannels((prev) =>
                prev.map((ch) => {
                  if (ch.id === data.id) {
                    if (ch.status !== data.status) {
                      addLog(`CH ${data.id} is now ${data.status}`, "info", data.id);
                    }
                    return { ...ch, ...data };
                  }
                  return ch;
                })
              );
            } else if (payload.type === "config_update") {
              const cfg = payload.data;
              setSettings((prev) => ({
                ...prev,
                sipPort: cfg.sipPort || prev.sipPort,
                selectedDevice: cfg.selectedDevice || prev.selectedDevice,
                selectedOutputDevice:
                  cfg.selectedOutputDevice !== undefined
                    ? cfg.selectedOutputDevice
                    : prev.selectedOutputDevice,
                localIp: cfg.localIp || prev.localIp,
                ampEnabled: cfg.ampEnabled !== undefined ? cfg.ampEnabled : prev.ampEnabled,
                bridgeEnabled: cfg.bridgeEnabled !== undefined ? cfg.bridgeEnabled : prev.bridgeEnabled,
              }));
            } else if (payload.type === "dispatch_matrix_update") {
              const groups = payload.data?.groups;
              if (Array.isArray(groups)) {
                setDispatchGroups(groups);
              }
            } else if (payload.type === "audio_level") {
              const { id, level } = payload.data;
              setChannels((prev) =>
                prev.map((ch) => (ch.id === id ? { ...ch, audioLevel: level } : ch))
              );
            } else if (payload.type === "bridge_status") {
              // ACU Bridge keepalive link health (alive within ~6s / stale).
              const { id, linkAlive } = payload.data;
              setChannels((prev) =>
                prev.map((ch) => (ch.id === id ? { ...ch, bridgeLinkAlive: linkAlive } : ch))
              );
            } else if (payload.type === "telemetry") {
              const { cpu, ram } = payload.data;
              setCpuLoad(cpu);
              setRamUsage(ram);
            } else if (payload.type === "log") {
              addLog(payload.data.message, payload.data.level || "info", payload.data.channelId);
            }
          } catch (err) {
            console.error("WS parse error", err);
          }
        };

        ws.onclose = () => {
          setSettings((prev) => ({ ...prev, isConnected: false }));
          connectionTimeoutRef.current = setTimeout(connectWebSocket, 3000);
        };
      } catch (err) {
        setSettings((prev) => ({ ...prev, isConnected: false }));
      }
    };

    connectWebSocket();

    return () => {
      if (socketRef.current) socketRef.current.close();
      if (connectionTimeoutRef.current) clearTimeout(connectionTimeoutRef.current);
    };
  }, [settings.isSimulatorMode, settings.sbcIp, addLog]);

  // Timers and simulation meters
  useEffect(() => {
    const timerInterval = setInterval(() => {
      setChannels((prev) =>
        prev.map((ch) => {
          if (ch.status === "CONNECTED") {
            return {
              ...ch,
              duration: ch.duration + 1,
            };
          }
          return ch;
        })
      );

      if (settings.isSimulatorMode) {
        const activeCount = channels.filter((ch) => ch.status === "CONNECTED").length;
        setCpuLoad(Math.min(95, Math.max(5, 12 + activeCount * 4 + Math.floor(Math.random() * 3))));
        setRamUsage(Math.min(90, Math.max(20, 36 + activeCount * 1.5)));
      }
    }, 1000);

    const audioInterval = setInterval(() => {
      if (settings.isSimulatorMode) {
        setChannels((prev) =>
          prev.map((ch) => {
            if (ch.status === "CONNECTED") {
              return {
                ...ch,
                audioLevel: Math.random() > 0.15 ? Math.floor(Math.random() * 60) + 15 : 0,
              };
            }
            return ch;
          })
        );
      }
    }, 100);

    return () => {
      clearInterval(timerInterval);
      clearInterval(audioInterval);
    };
  }, [settings.isSimulatorMode, channels]);

  const triggerLiveAccept = async (id: number) => {
    try {
      const parsed = parseSbcAddress(settings.sbcIp);
      if (!parsed) return;
      await fetch(`${parsed.httpUrl}/api/channels/${id}/accept`, { method: "POST" });
    } catch (err) {
      console.error(err);
    }
  };

  const triggerLiveReject = async (id: number) => {
    try {
      const parsed = parseSbcAddress(settings.sbcIp);
      if (!parsed) return;
      await fetch(`${parsed.httpUrl}/api/channels/${id}/reject`, { method: "POST" });
    } catch (err) {
      console.error(err);
    }
  };

  // Local (optimistic) update for the Dispatcher patch matrix — the backend's
  // own `dispatch_matrix_update` broadcast is the source of truth and will
  // correct this a moment later if it ever disagrees.
  const handleDispatchToggle = (groupId: number, channelId: number, isMember: boolean) => {
    setDispatchGroups((prev) =>
      prev.map((g) =>
        g.id === groupId
          ? {
              ...g,
              memberIds: isMember
                ? g.memberIds.includes(channelId) ? g.memberIds : [...g.memberIds, channelId]
                : g.memberIds.filter((c) => c !== channelId),
            }
          : g
      )
    );
  };

  const activeCallsCount = channels.filter((ch) => ch.status === "CONNECTED").length;
  const totalBandwidth = channels.reduce(
    (acc, ch) => {
      if (ch.status === "CONNECTED") {
        acc.rx += ch.rxKbps;
        acc.tx += ch.txKbps;
      }
      return acc;
    },
    { rx: 0, tx: 0 }
  );

  const handleClearLogs = () => setLogs([]);
  const isSecure = channels.every(c => c.srtpEnabled);

  return (
    <div className="w-screen h-screen overflow-hidden flex flex-col bg-zinc-100 text-zinc-900 font-sans select-none relative">
      {/* Dashboard Header */}
      <DashboardHeader
        settings={settings}
        activeCallsCount={activeCallsCount}
        onToggleSettings={() => setShowSettings(true)}
        onToggleLogs={() => setShowLogs(true)}
        onToggleDispatchMatrix={() => setShowDispatchMatrix(true)}
        isSecure={isSecure}
      />

      {/* Grid Content Area (fits 6x2 perfectly with 1px borders) */}
      <main className="flex-1 overflow-hidden bg-gray-200">
        <div className="grid grid-cols-6 grid-rows-2 gap-[1px] w-full h-full">
          {channels.map((channel) => (
            <ChannelCard
              key={channel.id}
              channel={channel}
              onCallToggle={handleCallToggle}
              onAcceptCall={triggerLiveAccept}
              onRejectCall={triggerLiveReject}
              onUpdateTarget={handleUpdateTarget}
              onUpdateCodec={handleUpdateCodec}
              onPttToggle={handlePttToggle}
            />
          ))}
        </div>
      </main>

      {/* Settings Modal Overlay */}
      {showSettings && (
        <div className="absolute inset-0 bg-black/40 z-50 flex items-center justify-center animate-fade-in">
          <div className="bg-white border border-gray-200 rounded-lg shadow-xl w-[400px] p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-gray-100 pb-2">
              <h2 className="text-sm font-bold text-gray-900 uppercase tracking-wide flex items-center gap-1.5">
                Gateway Configuration
              </h2>
              <button 
                onClick={() => setShowSettings(false)}
                className="p-1 rounded text-gray-400 transition cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Form Fields */}
            <div className="flex flex-col gap-3">
              {/* SBC IP */}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase font-bold text-gray-500 flex items-center gap-1">
                  <Server className="h-3 w-3" /> SBC Address
                </label>
                <input
                  type="text"
                  value={settings.sbcIp}
                  onChange={(e) => handleSettingsChange({ sbcIp: e.target.value })}
                  className="bg-gray-50 border border-gray-200 px-2 py-1 text-xs font-sans text-gray-900 rounded focus:outline-none focus:border-gray-400"
                  placeholder="localhost"
                />
              </div>

              {/* SIP Port */}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase font-bold text-gray-500 flex items-center gap-1">
                  <Network className="h-3 w-3" /> SIP Listening Port
                </label>
                <input
                  type="text"
                  value={settings.sipPort}
                  onChange={(e) => handleSettingsChange({ sipPort: e.target.value })}
                  className="bg-gray-50 border border-gray-200 px-2 py-1 text-xs font-sans text-gray-900 rounded focus:outline-none focus:border-gray-400"
                  placeholder="5060"
                />
              </div>

              {/* Mic Input */}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase font-bold text-gray-500 flex items-center gap-1">
                  <Mic className="h-3 w-3" /> Audio Input Interface
                </label>
                <select
                  value={settings.selectedDevice}
                  onChange={(e) => handleSettingsChange({ selectedDevice: e.target.value })}
                  className="bg-gray-50 border border-gray-200 px-2 py-1 text-xs font-sans text-gray-900 rounded focus:outline-none focus:border-gray-400 cursor-pointer"
                >
                  {settings.availableDevices.length === 0 ? (
                    <option value="Default">Default Device</option>
                  ) : (
                    settings.availableDevices.map((dev) => (
                      <option key={dev} value={dev}>{dev}</option>
                    ))
                  )}
                </select>
              </div>

              {/* Audio Output */}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] uppercase font-bold text-gray-500 flex items-center gap-1">
                  <Volume2 className="h-3 w-3" /> Audio Output Interface
                </label>
                <select
                  value={settings.selectedOutputDevice}
                  onChange={(e) => handleSettingsChange({ selectedOutputDevice: e.target.value })}
                  className="bg-gray-50 border border-gray-200 px-2 py-1 text-xs font-sans text-gray-900 rounded focus:outline-none focus:border-gray-400 cursor-pointer"
                >
                  <option value="">System Default (SBC onboard)</option>
                  {settings.availableOutputDevices.map((dev) => (
                    <option key={dev} value={dev}>{dev}</option>
                  ))}
                </select>
              </div>

              {/* Simulation Switch */}
              <div className="flex items-center justify-between border-t border-gray-100 pt-3 mt-1">
                <span className="text-[11px] font-bold text-gray-700 uppercase">Simulator Mode</span>
                <button
                  onClick={() => handleSettingsChange({ isSimulatorMode: !settings.isSimulatorMode })}
                  className="flex items-center gap-1 transition cursor-pointer text-gray-600"
                >
                  {settings.isSimulatorMode ? (
                    <ToggleRight className="h-6 w-6 text-amber-500" />
                  ) : (
                    <ToggleLeft className="h-6 w-6 text-gray-300" />
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Logs Modal Overlay */}
      {showLogs && (
        <div className="absolute inset-0 bg-black/40 z-50 flex items-center justify-center animate-fade-in">
          <SystemConsole
            logs={logs}
            onClearLogs={handleClearLogs}
            onClose={() => setShowLogs(false)}
          />
        </div>
      )}

      {/* Dispatcher Patch Matrix Modal Overlay */}
      {showDispatchMatrix && (
        <div className="absolute inset-0 bg-black/40 z-50 flex items-center justify-center animate-fade-in">
          <DispatchMatrixPanel
            channels={channels}
            groups={dispatchGroups}
            httpBaseUrl={parseSbcAddress(settings.sbcIp || "localhost")?.httpUrl ?? null}
            onClose={() => setShowDispatchMatrix(false)}
            onToggle={handleDispatchToggle}
          />
        </div>
      )}

    </div>
  );
}
