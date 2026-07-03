"use client";

interface AudioMeterProps {
  level: number; // 0 to 100
  isActive: boolean;
}

export function AudioMeter({ level, isActive }: AudioMeterProps) {
  const segmentCount = 10;
  const activeSegments = isActive ? Math.round((level / 100) * segmentCount) : 0;

  return (
    <div className="flex flex-col items-center gap-1 bg-mil-inset p-2 rounded-none border border-mil-border w-10">
      <div className="text-[9px] font-mono text-mil-muted font-bold uppercase tracking-wider select-none mb-1">
        VU
      </div>
      <div className="flex flex-col-reverse gap-[2px] h-[100px] w-full">
        {Array.from({ length: segmentCount }).map((_, index) => {
          const segmentIndex = index + 1;
          const isLit = segmentIndex <= activeSegments;

          let litColor = "bg-mil-white";
          let dimColor = "bg-mil-bezel border-mil-border/50";

          if (segmentIndex > 8) {
            // Red alert zones
            litColor = "bg-mil-red";
          } else if (segmentIndex > 7) {
            // Amber warning zones
            litColor = "bg-mil-amber";
          }

          return (
            <div
              key={index}
              className={`h-[7px] w-full rounded-none border-none transition-all duration-75 ${
                isLit ? litColor : dimColor
              }`}
            />
          );
        })}
      </div>
    </div>
  );
}
