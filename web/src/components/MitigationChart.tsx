import { useMemo, useState } from 'react';
import type { RateCI, SummaryRow } from '../types';
import { fmtCI, fmtPct, fmtReduction } from '../lib/format';

interface MitigationChartProps {
  rows: SummaryRow[];
  groupBy?: string[];
  title?: string;
  subtitle?: string;
}

interface HoveredBar {
  rowLabel: string;
  mitigation: string;
  seriesLabel: string;
  color: string;
  metric: RateCI;
  reduction: number | null;
  nEpisodes: number;
  nErrors: number;
}

const SERIES: Array<{
  key: 'reached' | 'used' | 'misaligned';
  label: string;
  color: string;
}> = [
  { key: 'reached', label: 'Reached Outside', color: '#f59e0b' },
  { key: 'used', label: 'Used', color: '#f97316' },
  { key: 'misaligned', label: 'Misaligned Use', color: '#ef4444' },
];

const TICKS = [0, 25, 50, 75, 100];

export function MitigationChart({
  rows,
  groupBy = ['model', 'mitigation_set_id'],
  title = 'Escape & Misalignment Rates by Model × Mitigation',
  subtitle = 'Grouped horizontal bars with 95% Wilson score confidence intervals. Hover any bar for exact counts.',
}: MitigationChartProps) {
  const [hovered, setHovered] = useState<HoveredBar | null>(null);

  const layout = useMemo(() => {
    const svgWidth = 920;
    const leftMargin = 250;
    const rightMargin = 115;
    const topMargin = 42;
    const bottomMargin = 32;
    const plotWidth = svgWidth - leftMargin - rightMargin;
    const barH = 12;
    const barGap = 4;
    const groupPad = 20;
    const groupH = SERIES.length * barH + (SERIES.length - 1) * barGap + groupPad;
    const svgHeight = Math.max(130, topMargin + rows.length * groupH + bottomMargin);
    const plotBottom = topMargin + rows.length * groupH - groupPad / 2;
    return {
      svgWidth,
      leftMargin,
      rightMargin,
      topMargin,
      bottomMargin,
      plotWidth,
      barH,
      barGap,
      groupPad,
      groupH,
      svgHeight,
      plotBottom,
    };
  }, [rows.length]);

  const rowLabelFor = (row: SummaryRow): { primary: string; secondary: string; full: string } => {
    if (groupBy.includes('model') && groupBy.includes('mitigation_set_id')) {
      const m = row.group.model ?? '—';
      const mit = row.group.mitigation_set_id ?? '—';
      return { primary: m, secondary: mit, full: `${m} · ${mit}` };
    }
    const vals = groupBy.map((k) => row.group[k] ?? '—');
    return {
      primary: vals[0] ?? 'all',
      secondary: vals.slice(1).join(' / '),
      full: vals.join(' · '),
    };
  };

  return (
    <section className="rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-5">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-zinc-100">{title}</h2>
          <p className="mt-0.5 text-xs text-zinc-400">{subtitle}</p>
        </div>

        {/* Live hover readout pill */}
        <div className="min-h-[38px] shrink-0 rounded-lg border border-zinc-800 bg-zinc-950/90 px-3 py-1.5 text-xs">
          {hovered ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono tabular-nums">
              <span className="inline-flex items-center gap-1.5 font-sans font-medium text-zinc-200">
                <span
                  className="inline-block h-2.5 w-2.5 rounded-xs"
                  style={{ backgroundColor: hovered.color }}
                />
                {hovered.rowLabel}
              </span>
              <span className="text-zinc-400">{hovered.seriesLabel}:</span>
              <span className="font-semibold text-zinc-100">
                {fmtPct(hovered.metric)} ({hovered.metric.k}/{hovered.metric.n})
              </span>
              <span className="text-zinc-400">CI {fmtCI(hovered.metric)}</span>
              {hovered.reduction !== null && (
                <span className="text-emerald-400">
                  vs none: {fmtReduction(hovered.reduction)}
                </span>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-4 text-zinc-400">
              {SERIES.map((s) => (
                <span key={s.key} className="inline-flex items-center gap-1.5">
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-xs"
                    style={{ backgroundColor: s.color }}
                  />
                  <span>{s.label}</span>
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5">
                <span className="inline-block h-0.5 w-3 bg-zinc-200" />
                <span>95% Wilson CI</span>
              </span>
            </div>
          )}
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-lg border border-dashed border-zinc-800 text-xs text-zinc-500">
          No summary rows match the current filter selection.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <svg
            viewBox={`0 0 ${layout.svgWidth} ${layout.svgHeight}`}
            className="block h-auto min-w-[680px] w-full"
            role="img"
            aria-label={title}
            onMouseLeave={() => setHovered(null)}
          >
            {/* Vertical grid lines & axis labels */}
            {TICKS.map((tick) => {
              const x = layout.leftMargin + (tick / 100) * layout.plotWidth;
              return (
                <g key={tick}>
                  <line
                    x1={x}
                    y1={layout.topMargin - 12}
                    x2={x}
                    y2={layout.plotBottom}
                    stroke="#27272a"
                    strokeWidth={1}
                    strokeDasharray={tick === 0 ? undefined : '3 3'}
                  />
                  <text
                    x={x}
                    y={layout.topMargin - 20}
                    textAnchor="middle"
                    className="fill-zinc-500 font-mono text-[10px]"
                  >
                    {tick}%
                  </text>
                  <text
                    x={x}
                    y={layout.plotBottom + 18}
                    textAnchor="middle"
                    className="fill-zinc-500 font-mono text-[10px]"
                  >
                    {tick}%
                  </text>
                </g>
              );
            })}

            {/* Rows */}
            {rows.map((row, rowIdx) => {
              const rowTop = layout.topMargin + rowIdx * layout.groupH;
              const blockH = SERIES.length * layout.barH + (SERIES.length - 1) * layout.barGap;
              const label = rowLabelFor(row);
              const isRowHovered = hovered?.rowLabel === label.full;

              return (
                <g key={`${label.full}-${rowIdx}`}>
                  {/* Subtle alternating row highlight */}
                  <rect
                    x={0}
                    y={rowTop - 6}
                    width={layout.svgWidth}
                    height={blockH + 12}
                    rx={6}
                    fill={
                      isRowHovered
                        ? 'rgba(255,255,255,0.045)'
                        : rowIdx % 2 === 1
                          ? 'rgba(255,255,255,0.015)'
                          : 'transparent'
                    }
                  />

                  {/* Left group label */}
                  <text
                    x={layout.leftMargin - 14}
                    y={rowTop + blockH / 2 - (label.secondary ? 3 : -4)}
                    textAnchor="end"
                    className="fill-zinc-100 text-[12px] font-medium"
                  >
                    {label.primary.length > 28 ? `${label.primary.slice(0, 26)}…` : label.primary}
                  </text>
                  {label.secondary && (
                    <text
                      x={layout.leftMargin - 14}
                      y={rowTop + blockH / 2 + 12}
                      textAnchor="end"
                      className="fill-zinc-400 font-mono text-[10.5px]"
                    >
                      {label.secondary.length > 30
                        ? `${label.secondary.slice(0, 28)}…`
                        : label.secondary}
                    </text>
                  )}

                  {/* Bars for each tier */}
                  {SERIES.map((series, sIdx) => {
                    const metric = row[series.key];
                    const y = rowTop + sIdx * (layout.barH + layout.barGap);
                    const midY = y + layout.barH / 2;

                    if (!metric || metric.n <= 0) {
                      return (
                        <text
                          key={series.key}
                          x={layout.leftMargin + 6}
                          y={midY + 3.5}
                          className="fill-zinc-600 font-mono text-[10px]"
                        >
                          N/A
                        </text>
                      );
                    }

                    const clampedRate = Math.max(0, Math.min(1, metric.rate));
                    const clampedLo = Math.max(0, Math.min(1, metric.lo));
                    const clampedHi = Math.max(0, Math.min(1, metric.hi));
                    const barW = clampedRate * layout.plotWidth;
                    const loX = layout.leftMargin + clampedLo * layout.plotWidth;
                    const hiX = layout.leftMargin + clampedHi * layout.plotWidth;
                    const textX = Math.max(layout.leftMargin + barW, hiX) + 8;

                    const isThisHovered =
                      hovered?.rowLabel === label.full && hovered?.seriesLabel === series.label;

                    return (
                      <g
                        key={series.key}
                        className="cursor-pointer"
                        onMouseEnter={() =>
                          setHovered({
                            rowLabel: label.full,
                            mitigation: row.group.mitigation_set_id ?? '',
                            seriesLabel: series.label,
                            color: series.color,
                            metric,
                            reduction: row.reached_reduction_vs_none,
                            nEpisodes: row.n_episodes,
                            nErrors: row.n_errors,
                          })
                        }
                      >
                        {/* Invisible wider hover hit area */}
                        <rect
                          x={layout.leftMargin}
                          y={y - 1}
                          width={layout.plotWidth + layout.rightMargin - 8}
                          height={layout.barH + 2}
                          fill="transparent"
                        />

                        {/* Bar fill */}
                        <rect
                          x={layout.leftMargin}
                          y={y}
                          width={Math.max(barW, 2)}
                          height={layout.barH}
                          rx={3}
                          fill={series.color}
                          opacity={isThisHovered ? 1 : 0.84}
                        />

                        {/* 95% Wilson CI whisker */}
                        <line
                          x1={loX}
                          y1={midY}
                          x2={hiX}
                          y2={midY}
                          stroke="#e4e4e7"
                          strokeWidth={1.35}
                          strokeOpacity={0.9}
                        />
                        <line
                          x1={loX}
                          y1={midY - 3.2}
                          x2={loX}
                          y2={midY + 3.2}
                          stroke="#e4e4e7"
                          strokeWidth={1.35}
                          strokeOpacity={0.9}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 3.2}
                          x2={hiX}
                          y2={midY + 3.2}
                          stroke="#e4e4e7"
                          strokeWidth={1.35}
                          strokeOpacity={0.9}
                        />

                        {/* Numeric readout */}
                        <text
                          x={textX}
                          y={midY + 3.5}
                          className="fill-zinc-300 font-mono text-[10.5px] tabular-nums"
                        >
                          {fmtPct(metric)} ({metric.k}/{metric.n})
                        </text>
                      </g>
                    );
                  })}
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </section>
  );
}
