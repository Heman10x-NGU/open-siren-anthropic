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
  { key: 'reached', label: 'Reached Outside', color: '#525252' },
  { key: 'used', label: 'Used Honeypot', color: '#141414' },
  { key: 'misaligned', label: 'Misaligned Use', color: '#eb6c36' },
];

const TICKS = [0, 25, 50, 75, 100];

export function MitigationChart({
  rows,
  groupBy = ['model', 'mitigation_set_id'],
  title = 'Escape & misalignment rates by model and mitigation',
  subtitle = 'Grouped horizontal bars with 95% Wilson score confidence intervals. Hover any bar for exact counts.',
}: MitigationChartProps) {
  const [hovered, setHovered] = useState<HoveredBar | null>(null);

  const layout = useMemo(() => {
    const svgWidth = 960;
    const leftMargin = 240;
    const rightMargin = 122;
    const topMargin = 38;
    const bottomMargin = 30;
    const plotWidth = svgWidth - leftMargin - rightMargin;
    const barH = 11;
    const barGap = 4;
    const groupPad = 22;
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
    <section className="rounded-[6px] border border-[#141414]/[0.14] bg-white p-5">
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-[22px] leading-tight text-[#141414]">{title}</h2>
          <p className="mt-1 text-xs text-[#737373]">{subtitle}</p>
        </div>

        {/* Live hover readout / legend */}
        <div className="min-h-[34px] shrink-0 rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-3 py-1.5 text-xs">
          {hovered ? (
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[11px] tabular-nums">
              <span className="inline-flex items-center gap-1.5 font-sans font-medium text-[#141414]">
                <span
                  className="inline-block h-2 w-2 rounded-[1px]"
                  style={{ backgroundColor: hovered.color }}
                />
                {hovered.rowLabel}
              </span>
              <span className="text-[#737373]">{hovered.seriesLabel}:</span>
              <span className="font-semibold text-[#141414]">
                {fmtPct(hovered.metric)} ({hovered.metric.k}/{hovered.metric.n})
              </span>
              <span className="text-[#737373]">CI {fmtCI(hovered.metric)}</span>
              {hovered.reduction !== null && (
                <span className="text-[#525252]">
                  vs none {fmtReduction(hovered.reduction)}
                </span>
              )}
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[#525252]">
              {SERIES.map((s) => (
                <span key={s.key} className="inline-flex items-center gap-1.5">
                  <span
                    className="inline-block h-2 w-2 rounded-[1px]"
                    style={{ backgroundColor: s.color }}
                  />
                  <span>{s.label}</span>
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5 text-[#737373]">
                <span className="inline-block h-[1px] w-3 bg-[#141414]" />
                <span>95% Wilson CI</span>
              </span>
            </div>
          )}
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-[4px] border border-dashed border-[#d4d4d4] text-xs text-[#737373]">
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
            {/* Vertical grid lines & axis ticks */}
            {TICKS.map((tick) => {
              const x = layout.leftMargin + (tick / 100) * layout.plotWidth;
              return (
                <g key={tick}>
                  <line
                    x1={x}
                    y1={layout.topMargin - 10}
                    x2={x}
                    y2={layout.plotBottom}
                    stroke={tick === 0 ? '#d4d4d4' : '#e5e5e5'}
                    strokeWidth={1}
                    strokeDasharray={tick === 0 ? undefined : '2 3'}
                  />
                  <text
                    x={x}
                    y={layout.topMargin - 18}
                    textAnchor="middle"
                    className="fill-[#737373] font-mono text-[10px] tabular-nums"
                  >
                    {tick}%
                  </text>
                  <text
                    x={x}
                    y={layout.plotBottom + 18}
                    textAnchor="middle"
                    className="fill-[#737373] font-mono text-[10px] tabular-nums"
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
                  {/* Subtle hover row tint */}
                  <rect
                    x={0}
                    y={rowTop - 7}
                    width={layout.svgWidth}
                    height={blockH + 14}
                    rx={4}
                    fill={isRowHovered ? '#fafaf9' : 'transparent'}
                  />

                  {/* Subtle horizontal divider between groups */}
                  {rowIdx > 0 && (
                    <line
                      x1={0}
                      y1={rowTop - layout.groupPad / 2}
                      x2={layout.svgWidth}
                      y2={rowTop - layout.groupPad / 2}
                      stroke="#f0f0ef"
                      strokeWidth={1}
                    />
                  )}

                  {/* Left group label */}
                  <text
                    x={layout.leftMargin - 14}
                    y={rowTop + blockH / 2 - (label.secondary ? 3 : -4)}
                    textAnchor="end"
                    className="fill-[#141414] text-[12px] font-medium"
                  >
                    {label.primary.length > 28 ? `${label.primary.slice(0, 26)}…` : label.primary}
                  </text>
                  {label.secondary && (
                    <text
                      x={layout.leftMargin - 14}
                      y={rowTop + blockH / 2 + 12}
                      textAnchor="end"
                      className="fill-[#737373] font-mono text-[10.5px]"
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
                          x={layout.svgWidth - 6}
                          y={midY + 3.5}
                          textAnchor="end"
                          className="fill-[#a3a3a3] font-mono text-[10px]"
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
                          y={y - 1.5}
                          width={layout.plotWidth + layout.rightMargin}
                          height={layout.barH + 3}
                          fill="transparent"
                        />

                        {/* Bar fill */}
                        <rect
                          x={layout.leftMargin}
                          y={y}
                          width={barW > 0 ? Math.max(barW, 2) : 0}
                          height={layout.barH}
                          rx={1.5}
                          fill={series.color}
                          opacity={isThisHovered ? 1 : 0.9}
                        />

                        {/* 95% Wilson CI whisker halo (keeps 1px ink stem legible over dark bars) */}
                        <line
                          x1={loX}
                          y1={midY}
                          x2={hiX}
                          y2={midY}
                          stroke="#ffffff"
                          strokeWidth={2.6}
                          strokeOpacity={0.85}
                        />
                        <line
                          x1={loX}
                          y1={midY - 3}
                          x2={loX}
                          y2={midY + 3}
                          stroke="#ffffff"
                          strokeWidth={2.6}
                          strokeOpacity={0.85}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 3}
                          x2={hiX}
                          y2={midY + 3}
                          stroke="#ffffff"
                          strokeWidth={2.6}
                          strokeOpacity={0.85}
                        />

                        {/* Crisp 1px Wilson CI stem & caps */}
                        <line
                          x1={loX}
                          y1={midY}
                          x2={hiX}
                          y2={midY}
                          stroke="#141414"
                          strokeWidth={1}
                        />
                        <line
                          x1={loX}
                          y1={midY - 3}
                          x2={loX}
                          y2={midY + 3}
                          stroke="#141414"
                          strokeWidth={1}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 3}
                          x2={hiX}
                          y2={midY + 3}
                          stroke="#141414"
                          strokeWidth={1}
                        />

                        {/* Right-aligned numeric readout */}
                        <text
                          x={layout.svgWidth - 6}
                          y={midY + 3.5}
                          textAnchor="end"
                          className={`font-mono text-[10.5px] tabular-nums ${
                            series.key === 'misaligned' && metric.rate > 0
                              ? 'fill-[#eb6c36] font-medium'
                              : isThisHovered
                                ? 'fill-[#141414] font-medium'
                                : 'fill-[#525252]'
                          }`}
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
