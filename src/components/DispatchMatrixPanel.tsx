"use client";

import { X, GitMerge } from "lucide-react";
import { ChannelState, DispatchGroup } from "@/lib/types";

interface DispatchMatrixPanelProps {
  channels: ChannelState[];
  groups: DispatchGroup[];
  httpBaseUrl: string | null;
  onClose: () => void;
  /** Optimistic local update — applied immediately on click, then reconciled
   * (or reverted) once the backend responds. The backend's own broadcast
   * (`dispatch_matrix_update`) is the ultimate source of truth and will
   * correct any drift a moment later regardless. */
  onToggle: (groupId: number, channelId: number, isMember: boolean) => void;
}

export function DispatchMatrixPanel({
  channels,
  groups,
  httpBaseUrl,
  onClose,
  onToggle,
}: DispatchMatrixPanelProps) {
  const handleCellClick = async (groupId: number, channelId: number) => {
    if (!httpBaseUrl) return;
    const group = groups.find((g) => g.id === groupId);
    const wasMember = group ? group.memberIds.includes(channelId) : false;
    const optimisticNext = !wasMember;

    // Instant, no save/reload — apply immediately for emergency responsiveness.
    onToggle(groupId, channelId, optimisticNext);

    try {
      const res = await fetch(`${httpBaseUrl}/api/dispatch/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ groupId, channelId }),
      });
      if (res.ok) {
        const data = await res.json();
        if (typeof data.isMember === "boolean" && data.isMember !== optimisticNext) {
          onToggle(groupId, channelId, data.isMember);
        }
      } else {
        onToggle(groupId, channelId, wasMember);
      }
    } catch (err) {
      onToggle(groupId, channelId, wasMember);
    }
  };

  return (
    <div className="bg-white border border-gray-200 shadow-xl w-[340px] max-h-[460px] flex flex-col">
      <div className="flex items-center justify-between border-b border-gray-200 px-2 py-1.5 shrink-0">
        <h2 className="text-[11px] font-bold text-gray-900 uppercase tracking-wide flex items-center gap-1">
          <GitMerge className="h-3 w-3" /> Patch Matrix
        </h2>
        <button
          onClick={onClose}
          className="p-0.5 text-gray-400 transition cursor-pointer"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="flex-1 overflow-auto p-1.5">
        {groups.length === 0 ? (
          <div className="text-[10px] text-gray-400 text-center py-8">Loading&hellip;</div>
        ) : (
          <table className="border-collapse w-full">
            <thead>
              <tr>
                <th className="text-[8px] font-bold uppercase text-gray-400 w-6 sticky top-0 bg-white"></th>
                {groups.map((g) => (
                  <th
                    key={g.id}
                    className="text-[8px] font-bold uppercase text-gray-400 pb-1 text-center sticky top-0 bg-white leading-tight"
                    title={g.name}
                  >
                    {g.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {channels.map((ch) => (
                <tr key={ch.id}>
                  <td className="text-[10px] font-bold text-gray-700 text-center border border-gray-200 bg-gray-50 w-6 h-6">
                    {ch.id}
                  </td>
                  {groups.map((g) => {
                    const isMember = g.memberIds.includes(ch.id);
                    return (
                      <td key={g.id} className="p-0">
                        <button
                          type="button"
                          onClick={() => handleCellClick(g.id, ch.id)}
                          title={`CH${ch.id} ↔ ${g.name}`}
                          className={`block w-full h-6 min-w-[26px] border transition cursor-pointer ${
                            isMember
                              ? "bg-emerald-500 border-emerald-600"
                              : "bg-gray-100 border-gray-200 active:bg-gray-200"
                          }`}
                        />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="px-2 py-1 text-[8.5px] text-gray-400 border-t border-gray-200 shrink-0">
        Tap a cell to patch/unpatch instantly &mdash; live on active calls, no save needed.
      </div>
    </div>
  );
}
