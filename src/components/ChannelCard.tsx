"use client";

import { useRef } from "react";
import { Mic, PhoneCall, PhoneForwarded, PhoneMissed, Volume2, Lock, Unlock } from "lucide-react";
import { ChannelState, CodecType } from "@/lib/types";

interface ChannelCardProps {
  channel: ChannelState;
  onCallToggle: (id: number, targetUri: string, codec: CodecType) => void;
  onAcceptCall: (id: number) => void;
  onRejectCall: (id: number) => void;
  onUpdateTarget: (id: number, targetUri: string) => void;
  onUpdateCodec: (id: number, codec: CodecType) => void;
  onPttToggle: (id: number, active: boolean) => void;
}

export function ChannelCard({
  channel,
  onCallToggle,
  onAcceptCall,
  onRejectCall,
  onPttToggle,
}: ChannelCardProps) {
  const {
    id,
    label,
    protocol = "SIP",
    targetUri,
    codec,
    status,
    duration,
    audioLevel,
    pttActive = false,
    volume = 100,
    srtpEnabled = true,
    ampStreaming = false,
  } = channel;

  const lastTapRef = useRef<number>(0);

  const handleCardInteraction = (e: React.MouseEvent | React.TouchEvent) => {
    const now = Date.now();
    const DOUBLE_TAP_DELAY = 300;

    if (now - lastTapRef.current < DOUBLE_TAP_DELAY) {
      // Double tap -> hangup/cancel/reject
      if (status === "CONNECTED" || status === "RINGING") {
        onCallToggle(id, targetUri, codec);
      } else if (status === "INCOMING") {
        onRejectCall(id);
      }
      lastTapRef.current = 0;
    } else {
      // Single tap -> call/accept
      lastTapRef.current = now;
      if (status === "IDLE" || status === "FAILED") {
        onCallToggle(id, targetUri, codec);
      } else if (status === "INCOMING") {
        onAcceptCall(id);
      }
    }
  };

  const handlePttStart = (e: React.MouseEvent | React.TouchEvent) => {
    if (status !== "CONNECTED") return;
    onPttToggle(id, true);
  };

  const handlePttEnd = () => {
    if (status !== "CONNECTED") return;
    onPttToggle(id, false);
  };

  const formatDuration = (secs: number) => {
    const m = Math.floor(secs / 60).toString().padStart(2, "0");
    const s = (secs % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
  };

  const isActive = status === "CONNECTED";
  const isRinging = status === "RINGING";
  const isIncoming = status === "INCOMING";
  const isFailed = status === "FAILED";
  const isIdle = status === "IDLE";

  let cardBgClass = "bg-white hover:bg-gray-50/50";
  let statusText = "STANDBY";
  let statusColorClass = "text-gray-400";
  let helperText = "TAP TO CALL";

  if (isActive) {
    if (pttActive) {
      cardBgClass = "bg-red-50 animate-pulse border-red-200";
      statusText = "TRANSMIT";
      statusColorClass = "text-red-600 font-extrabold";
      helperText = "RELEASE TO LISTEN";
    } else {
      cardBgClass = "bg-emerald-50/70 border-emerald-200";
      statusText = "ROUTING";
      statusColorClass = "text-emerald-700 font-extrabold";
      helperText = "HOLD CARD TO TALK";
    }
  } else if (isRinging) {
    cardBgClass = "bg-amber-50 animate-pulse border-amber-200";
    statusText = "DIALING";
    statusColorClass = "text-amber-600 font-extrabold";
    helperText = "DBL TAP TO CANCEL";
  } else if (isIncoming) {
    cardBgClass = "bg-amber-100 animate-pulse border-amber-300";
    statusText = "INCOMING";
    statusColorClass = "text-amber-800 font-black";
    helperText = "TAP OK • DBL TAP NO";
  } else if (isFailed) {
    cardBgClass = "bg-rose-50 border-rose-200";
    statusText = "FAILED";
    statusColorClass = "text-rose-600 font-extrabold";
    helperText = "TAP TO RETRY";
  }

  // Horizontal VU Meter
  const renderHorizontalVU = () => {
    const numBlocks = 12;
    const activeBlocks = isActive ? Math.round((audioLevel / 100) * numBlocks) : 0;
    
    return (
      <div className="flex gap-[2px] items-center h-2.5 w-full bg-gray-100 rounded-sm overflow-hidden p-[1px] border border-gray-200 shrink-0">
        {Array.from({ length: numBlocks }).map((_, i) => {
          const isLit = i < activeBlocks;
          let blockColor = "bg-emerald-500";
          if (i >= 10) blockColor = "bg-rose-500";
          else if (i >= 8) blockColor = "bg-amber-500";
          
          return (
            <div
              key={i}
              className={`h-full flex-1 transition-all duration-75 ${
                isLit ? blockColor : "bg-gray-200"
              }`}
            />
          );
        })}
      </div>
    );
  };

  const renderVolumeBar = () => {
    const numBlocks = 12;
    const activeBlocks = Math.round((volume / 100) * numBlocks);
    
    return (
      <div className="w-full flex flex-col gap-0.5 mt-0.5">
        <div className="flex justify-between items-center text-[7px] text-gray-400 font-bold select-none leading-none">
          <span>VOLUME</span>
          <span className="font-mono text-gray-500">{volume}%</span>
        </div>
        <div className="flex gap-[2px] items-center h-1.5 w-full bg-gray-100 rounded-sm overflow-hidden p-[1px] border border-gray-200 shrink-0">
          {Array.from({ length: numBlocks }).map((_, i) => {
            const isLit = i < activeBlocks;
            const blockColor = "bg-blue-500";
            return (
              <div
                key={i}
                className={`h-full flex-1 transition-all duration-75 ${
                  isLit ? blockColor : "bg-gray-200"
                }`}
              />
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div
      onClick={handleCardInteraction}
      onTouchStart={(e) => {
        if (isActive) handlePttStart(e);
      }}
      onTouchEnd={() => {
        if (isActive) handlePttEnd();
      }}
      onMouseDown={(e) => {
        if (isActive) handlePttStart(e);
      }}
      onMouseUp={() => {
        if (isActive) handlePttEnd();
      }}
      onMouseLeave={() => {
        if (isActive) handlePttEnd();
      }}
      className={`rounded-none flex flex-col justify-between items-center text-center h-full w-full py-4 px-3 font-sans select-none cursor-pointer transition-all duration-150 relative ${cardBgClass}`}
    >
      {/* Top Section: Label and Protocol Type */}
      <div className="flex flex-col items-center gap-1 shrink-0 relative w-full">
        {/* A-MP Recording Mirror Indicator */}
        {ampStreaming && (
          <div className="absolute left-0 top-0.5 flex items-center justify-center" title="A-MP Mirror Stream Active (recording to NP-C4I)">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
            </span>
          </div>
        )}
        {/* Security Indicator */}
        <div className="absolute right-0 top-0" title={srtpEnabled ? "Secure SRTP" : "Plaintext RTP"}>
          {srtpEnabled ? (
            <Lock className="h-3.5 w-3.5 text-emerald-600" />
          ) : (
            <Unlock className="h-3.5 w-3.5 text-rose-500 animate-pulse" />
          )}
        </div>
        <span className="text-base font-black text-gray-900 tracking-tight leading-none truncate block w-full pl-3 pr-4" title={label}>
          {label}
        </span>
        <span className={`text-[9px] uppercase px-1.5 py-[2px] leading-none border rounded select-none font-extrabold tracking-wider ${
          protocol === "SIP"
            ? "border-blue-200 text-blue-600 bg-blue-50"
            : "border-purple-200 text-purple-600 bg-purple-50"
        }`}>
          {protocol}
        </span>
      </div>

      {/* Middle Section: Communication Status (Large & Centered) */}
      <div className="flex flex-col items-center justify-center flex-1 my-2 min-w-0">
        <span className={`text-base uppercase leading-none tracking-widest select-none ${statusColorClass}`}>
          {statusText}
        </span>
        {isActive && (
          <span className="text-xs font-mono text-gray-800 font-extrabold bg-emerald-100/90 px-2 py-0.5 rounded mt-2 select-none">
            {formatDuration(duration)}
          </span>
        )}
      </div>

      {/* Bottom Section: VU meter, Volume bar, and Helpers */}
      <div className="w-full flex flex-col gap-1.5 shrink-0 items-center">
        {/* Volume Bar */}
        {renderVolumeBar()}
        {/* VU Meter */}
        {renderHorizontalVU()}

        {/* Footer Hint Text & Dynamic State Icon */}
        <div className="w-full flex items-center justify-between border-t border-gray-100 pt-2">
          <span className="text-[8px] font-bold text-gray-400 tracking-wider uppercase select-none">
            {helperText}
          </span>
          <div className="text-gray-400">
            {isIdle && <PhoneCall className="h-3.5 w-3.5 text-gray-300" />}
            {isRinging && <PhoneCall className="h-3.5 w-3.5 text-amber-500 animate-pulse" />}
            {isIncoming && <PhoneForwarded className="h-3.5 w-3.5 text-amber-600 animate-bounce" />}
            {isActive && (
              pttActive ? <Mic className="h-3.5 w-3.5 text-red-500" /> : <Volume2 className="h-3.5 w-3.5 text-emerald-500 animate-pulse" />
            )}
            {isFailed && <PhoneMissed className="h-3.5 w-3.5 text-rose-400" />}
          </div>
        </div>
      </div>
    </div>
  );
}
