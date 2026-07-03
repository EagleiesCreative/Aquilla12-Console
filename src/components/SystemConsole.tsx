"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle, Info, RefreshCw, Send, Trash2, X, XCircle } from "lucide-react";
import { LogEntry, LogLevel } from "@/lib/types";

interface SystemConsoleProps {
  logs: LogEntry[];
  onClearLogs: () => void;
  onClose?: () => void;
}

export function SystemConsole({ logs, onClearLogs, onClose }: SystemConsoleProps) {
  const [filter, setFilter] = useState<LogLevel | "all">("all");
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const filteredLogs = logs.filter((log) => {
    if (filter === "all") return true;
    return log.level === filter;
  });

  const getLevelBadge = (level: LogLevel) => {
    switch (level) {
      case "info":
        return <Info className="h-3 w-3 text-blue-500" />;
      case "success":
        return <CheckCircle className="h-3 w-3 text-emerald-500" />;
      case "warning":
        return <AlertTriangle className="h-3 w-3 text-amber-500" />;
      case "error":
        return <XCircle className="h-3 w-3 text-rose-500" />;
      case "sip_tx":
        return <Send className="h-3 w-3 text-indigo-500" />;
      case "sip_rx":
        return <RefreshCw className="h-3 w-3 text-amber-500 animate-spin" style={{ animationDuration: "4s" }} />;
      default:
        return null;
    }
  };

  const getLevelStyle = (level: LogLevel) => {
    switch (level) {
      case "info":
        return "text-blue-700";
      case "success":
        return "text-emerald-700";
      case "warning":
        return "text-amber-700 font-medium";
      case "error":
        return "text-rose-700 font-semibold";
      case "sip_tx":
        return "text-indigo-600 font-mono";
      case "sip_rx":
        return "text-amber-600 font-mono";
      default:
        return "text-gray-900";
    }
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg shadow-xl relative overflow-hidden flex flex-col h-[350px] w-[700px] max-w-[95vw] text-gray-900 z-50">
      {/* Terminal Title Bar */}
      <div className="bg-gray-50 border-b border-gray-200 px-4 py-2 flex items-center justify-between">
        <span className="font-sans text-xs font-bold text-gray-800 uppercase tracking-wider">
          System Event & Signaling Logs
        </span>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Filters */}
          <div className="flex bg-gray-100 border border-gray-200 p-[2px] rounded text-[9px] font-sans">
            {(["all", "info", "success", "warning", "error"] as const).map((opt) => (
              <button
                key={opt}
                onClick={() => setFilter(opt)}
                className={`px-1.5 py-0.5 rounded cursor-pointer uppercase ${
                  filter === opt 
                    ? "bg-white text-gray-950 font-bold shadow-sm" 
                    : "text-gray-500 hover:text-gray-800"
                }`}
              >
                {opt}
              </button>
            ))}
          </div>

          {/* Clear Button */}
          <button
            onClick={onClearLogs}
            className="flex items-center gap-1 hover:bg-gray-100 border border-gray-200 text-gray-600 px-2 py-0.5 rounded text-[9px] font-sans cursor-pointer transition uppercase"
            title="Clear Logs"
          >
            <Trash2 className="h-3 w-3 text-rose-500" /> Clear
          </button>

          {/* Close button */}
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 rounded hover:bg-gray-100 text-gray-500 hover:text-gray-800 transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Logs Scroll Container */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-3 font-mono text-[9px] leading-normal space-y-1 bg-gray-50"
      >
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-gray-400 italic select-none">
            No system events logged
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div key={log.id} className="flex items-start gap-1.5 py-0.5 border-b border-gray-100">
              <span className="text-gray-400 shrink-0 select-none">
                [{log.timestamp}]
              </span>
              <span className="shrink-0 mt-0.5">
                {getLevelBadge(log.level)}
              </span>
              {log.channelId !== undefined && (
                <span className="bg-gray-200 text-gray-700 font-bold px-1 rounded text-[8px] shrink-0 border border-gray-300">
                  CH {log.channelId.toString().padStart(2, "0")}
                </span>
              )}
              <span className={`${getLevelStyle(log.level)} break-all`}>
                {log.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
