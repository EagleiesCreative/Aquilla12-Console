"use client";

import { useEffect, useState } from "react";
import { Settings, Terminal, Wifi, Shield, ShieldAlert } from "lucide-react";
import { GlobalSettings } from "@/lib/types";

interface DashboardHeaderProps {
  settings: GlobalSettings;
  activeCallsCount: number;
  onToggleSettings: () => void;
  onToggleLogs: () => void;
  showLogsButton?: boolean;
  isSecure?: boolean;
}

export function DashboardHeader({
  settings,
  activeCallsCount,
  onToggleSettings,
  onToggleLogs,
  showLogsButton = true,
  isSecure = true,
}: DashboardHeaderProps) {
  const [localIp, setLocalIp] = useState("127.0.0.1");

  useEffect(() => {
    if (settings.localIp && settings.localIp !== "127.0.0.1" && settings.localIp !== "localhost" && !settings.localIp.startsWith("0.0.0.0")) {
      setLocalIp(settings.localIp);
    } else if (typeof window !== "undefined") {
      const hostname = window.location.hostname;
      if (hostname && hostname !== "localhost" && hostname !== "127.0.0.1" && !hostname.startsWith("0.0.0.0")) {
        setLocalIp(hostname);
      } else if (settings.sbcIp) {
        setLocalIp(settings.sbcIp);
      }
    }
  }, [settings.localIp, settings.sbcIp]);

  return (
    <header className="bg-white border-b border-gray-200 px-3 flex items-center justify-between select-none h-[34px] shrink-0 font-sans">
      {/* Brand & Active Call Count */}
      <div className="flex items-center gap-3">
        <span className="text-xs font-black text-gray-950 tracking-wider uppercase">
          AQUILLA-12
        </span>
        <div className="flex items-center gap-1 bg-emerald-50 border border-emerald-200 px-1.5 py-[1px] rounded-sm text-[9px] font-semibold text-emerald-700">
          <span>{activeCallsCount} Active</span>
        </div>
      </div>

      {/* Device Local IP Display */}
      <div className="text-[10px] text-gray-600 font-semibold flex items-center gap-1">
        <span className="text-gray-400 font-normal">IP:</span>
        <span className="font-mono text-gray-900">{localIp}</span>
      </div>

      {/* Header Actions */}
      <div className="flex items-center gap-3">
        {/* Security Shield */}
        <div className="flex items-center" title={isSecure ? "All Channels Secured (SRTP)" : "Plaintext RTP Active (Unsecured)"}>
          {isSecure ? (
            <Shield className="h-3.5 w-3.5 text-emerald-600 fill-emerald-50" />
          ) : (
            <ShieldAlert className="h-3.5 w-3.5 text-amber-500 animate-bounce" />
          )}
        </div>

        {/* Connection status dot */}
        <div className="flex items-center gap-1">
          <span className={`status-dot w-1.5 h-1.5 ${settings.isConnected ? "bg-emerald-500 animate-pulse" : "bg-rose-500"}`} />
          <span className="text-[8px] font-bold text-gray-400 uppercase">
            {settings.isSimulatorMode ? "SIM" : settings.isConnected ? "LIVE" : "OFFLINE"}
          </span>
        </div>

        {/* Logs Button */}
        {showLogsButton && (
          <button
            onClick={onToggleLogs}
            className="p-1 rounded hover:bg-gray-100 border border-gray-200 text-gray-600 transition cursor-pointer flex items-center justify-center h-5 w-5"
            title="Logs Console"
          >
            <Terminal className="h-3 w-3" />
          </button>
        )}

        {/* Settings button */}
        <button
          onClick={onToggleSettings}
          className="p-1 rounded hover:bg-gray-100 border border-gray-200 text-gray-600 transition cursor-pointer flex items-center justify-center h-5 w-5"
          title="Settings"
        >
          <Settings className="h-3 w-3" />
        </button>
      </div>
    </header>
  );
}
