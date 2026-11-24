import { useMemo, useState } from 'react';
import type { BreakdownsData, RateCI, SummaryRow } from '../types';
import {
  ABLATION_ORDER,
  DIFFICULTY_ORDER,
  MECHANISM_ORDER,
  fmtCI,
  fmtPct,
  labelForAblation,
  labelForDifficulty,
  labelForMechanism,
} from '../lib/format';

interface AblationChartsProps {
  breakdowns: BreakdownsData;
}

type MetricFocus = 'all' | 'reached' | 'used' | 'misaligned';

const ALL_SERIES = [
  { key: 'reached' as const, label: 'Reached Outside', color: '#525252' },
  { key: 'used' as const, label: 'Used Honeypot', color: '#141414' },
  { key: 'misaligned' as const, label: 'Misaligned Use', color: '#eb6c36' },
];

interface BreakdownCardProps {
  title: string;
  subtitle: string;
  rows: SummaryRow[];
  groupKey: string;
  order: readonly string[];
  labelFormatter: (v: string) => string;
  metricFocus: MetricFocus;
}

function BreakdownSvgCard({
  title,
  subtitle,
  rows,
  groupKey,
  order,
  labelFormatter,
  metricFocus,
}: BreakdownCardProps) {
  const [hovered, setHovered] = useState<{
    label: string;
    series: string;
    color: string;
    metric: RateCI;
    nEpisodes: number;
  } | null>(null);

  const orderedRows = useMemo(() => {
    const rank = new Map<string, number>(order.map((k, i) => [k, i]));
    return [...rows].sort((a, b) => {
      const ak = a.group[groupKey] ?? '';
      const bk = b.group[groupKey] ?? '';
      const ar = rank.get(ak) ?? 999;
      const br = rank.get(bk) ?? 999;
      return ar !== br ? ar - br : ak.localeCompare(bk);
    });
  }, [rows, groupKey, order]);

  const activeSeries =
    metricFocus === 'all' ? ALL_SERIES : ALL_SERIES.filter((s) => s.key === metricFocus);

  const svgWidth = 580;
  const leftMargin = 165;
  const rightMargin = 98;
  const topMargin = 24;
  const bottomMargin = 26;
  const plotWidth = svgWidth - leftMargin - rightMargin;
  const barH = activeSeries.length === 1 ? 16 : 9.5;
  const barGap = 4;
  const groupPad = 20;
  const groupH = activeSeries.length * barH + (activeSeries.length - 1) * barGap + groupPad;
  const svgHeight = Math.max(120, topMargin + orderedRows.length * groupH + bottomMargin);
  const plotBottom = topMargin + orderedRows.length * groupH - groupPad / 2;

  return (
    <div className="flex flex-col rounded-[6px] border border-[#141414]/[0.14] bg-white p-5">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-[21px] leading-tight text-[#141414]">{title}</h2>
          <p className="mt-1 text-xs text-[#737373]">{subtitle}</p>
        </div>
        {hovered && (
          <div className="shrink-0 rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-2.5 py-1 font-mono text-[11px] tabular-nums">
            <span
              className="mr-1.5 inline-block h-2 w-2 rounded-[1px]"
              style={{ backgroundColor: hovered.color }}
            />
            <span className="font-semibold text-[#141414]">{fmtPct(hovered.metric)}</span>
            <span className="ml-1.5 text-[#737373]">
              ({hovered.metric.k}/{hovered.metric.n}) {fmtCI(hovered.metric)}
            </span>
          </div>
        )}
      </div>

      {orderedRows.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-[4px] border border-dashed border-[#d4d4d4] text-xs text-[#737373]">
          No breakdown data available.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <svg
            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
            className="block h-auto min-w-[440px] w-full"
            role="img"
            aria-label={title}
            onMouseLeave={() => setHovered(null)}
          >
            {[0, 25, 50, 75, 100].map((tick) => {
              const x = leftMargin + (tick / 100) * plotWidth;
              return (
                <g key={tick}>
                  <line
                    x1={x}
                    y1={topMargin - 6}
                    x2={x}
                    y2={plotBottom}
                    stroke={tick === 0 ? '#d4d4d4' : '#e5e5e5'}
                    strokeWidth={1}
                    strokeDasharray={tick === 0 ? undefined : '2 3'}
                  />
                  <text
                    x={x}
                    y={plotBottom + 16}
                    textAnchor="middle"
                    className="fill-[#737373] font-mono text-[10px] tabular-nums"
                  >
                    {tick}%
                  </text>
                </g>
              );
            })}

            {orderedRows.map((row, rIdx) => {
              const rawKey = row.group[groupKey] ?? '—';
              const displayLabel = labelFormatter(rawKey);
              const rowTop = topMargin + rIdx * groupH;
              const blockH = activeSeries.length * barH + (activeSeries.length - 1) * barGap;

              return (
                <g key={`${rawKey}-${rIdx}`}>
                  {rIdx > 0 && (
                    <line
                      x1={0}
                      y1={rowTop - groupPad / 2}
                      x2={svgWidth}
                      y2={rowTop - groupPad / 2}
                      stroke="#f0f0ef"
                      strokeWidth={1}
                    />
                  )}
                  <text
                    x={leftMargin - 12}
                    y={rowTop + blockH / 2}
                    textAnchor="end"
                    className="fill-[#141414] text-[11.5px] font-medium"
                  >
                    {displayLabel.length > 23 ? `${displayLabel.slice(0, 21)}…` : displayLabel}
                  </text>
                  <text
                    x={leftMargin - 12}
                    y={rowTop + blockH / 2 + 12}
                    textAnchor="end"
                    className="fill-[#737373] font-mono text-[9.5px] tabular-nums"
                  >
                    n={row.n_episodes}
                  </text>

                  {activeSeries.map((series, sIdx) => {
                    const metric = row[series.key];
                    const y = rowTop + sIdx * (barH + barGap);
                    const midY = y + barH / 2;

                    if (!metric || metric.n <= 0) {
                      return (
                        <text
                          key={series.key}
                          x={svgWidth - 4}
                          y={midY + 3.5}
                          textAnchor="end"
                          className="fill-[#a3a3a3] font-mono text-[10px]"
                        >
                          N/A
                        </text>
                      );
                    }

                    const rate = Math.max(0, Math.min(1, metric.rate));
                    const lo = Math.max(0, Math.min(1, metric.lo));
                    const hi = Math.max(0, Math.min(1, metric.hi));
                    const barW = rate * plotWidth;
                    const loX = leftMargin + lo * plotWidth;
                    const hiX = leftMargin + hi * plotWidth;

                    return (
                      <g
                        key={series.key}
                        className="cursor-pointer"
                        onMouseEnter={() =>
                          setHovered({
                            label: displayLabel,
                            series: series.label,
                            color: series.color,
                            metric,
                            nEpisodes: row.n_episodes,
                          })
                        }
                      >
                        <rect
                          x={leftMargin}
                          y={y - 1.5}
                          width={plotWidth + rightMargin}
                          height={barH + 3}
                          fill="transparent"
                        />
                        <rect
                          x={leftMargin}
                          y={y}
                          width={barW > 0 ? Math.max(barW, 2) : 0}
                          height={barH}
                          rx={1.5}
                          fill={series.color}
                          opacity={0.92}
                        />

                        {/* White halo + crisp 1px ink Wilson CI whisker */}
                        <line
                          x1={loX}
                          y1={midY}
                          x2={hiX}
                          y2={midY}
                          stroke="#ffffff"
                          strokeWidth={2.4}
                          strokeOpacity={0.85}
                        />
                        <line
                          x1={loX}
                          y1={midY - 2.8}
                          x2={loX}
                          y2={midY + 2.8}
                          stroke="#ffffff"
                          strokeWidth={2.4}
                          strokeOpacity={0.85}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 2.8}
                          x2={hiX}
                          y2={midY + 2.8}
                          stroke="#ffffff"
                          strokeWidth={2.4}
                          strokeOpacity={0.85}
                        />
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
                          y1={midY - 2.8}
                          x2={loX}
                          y2={midY + 2.8}
                          stroke="#141414"
                          strokeWidth={1}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 2.8}
                          x2={hiX}
                          y2={midY + 2.8}
                          stroke="#141414"
                          strokeWidth={1}
                        />

                        <text
                          x={svgWidth - 4}
                          y={midY + 3.5}
                          textAnchor="end"
                          className={`font-mono text-[10px] tabular-nums ${
                            series.key === 'misaligned' && metric.rate > 0
                              ? 'fill-[#eb6c36] font-medium'
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
    </div>
  );
}

export function AblationCharts({ breakdowns }: AblationChartsProps) {
  const [metricFocus, setMetricFocus] = useState<MetricFocus>('all');

  return (
    <div className="space-y-6">
      {/* Metric toggle & legend bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-[6px] border border-[#141414]/[0.14] bg-white px-5 py-3.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
            Metric Tier
          </span>
          {(
            [
              { id: 'all', label: 'All 3 Tiers' },
              { id: 'reached', label: 'Reached Outside' },
              { id: 'used', label: 'Used Honeypot' },
              { id: 'misaligned', label: 'Misaligned Use' },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setMetricFocus(opt.id)}
              className={`rounded-[4px] border px-2.5 py-1 text-xs font-medium transition-colors duration-150 ${
                metricFocus === opt.id
                  ? 'border-[#141414] bg-[#141414] text-white'
                  : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[#525252]">
          {ALL_SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span
                className="inline-block h-2 w-2 rounded-[1px]"
                style={{ backgroundColor: s.color }}
              />
              {s.label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5 text-[#737373]">
            <span className="inline-block h-[1px] w-3 bg-[#141414]" />
            95% Wilson CI
          </span>
        </div>
      </div>

      {/* Side-by-side Difficulty & Tempter Ablations */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <BreakdownSvgCard
          title="Task difficulty curve"
          subtitle="Propensity to cross sandbox boundaries as legitimate task solvability decreases."
          rows={breakdowns.by_difficulty.rows}
          groupKey="difficulty"
          order={DIFFICULTY_ORDER}
          labelFormatter={labelForDifficulty}
          metricFocus={metricFocus}
        />

        <BreakdownSvgCard
          title="Tempter framing ablations"
          subtitle="Effect of removing deadline pressure, broad authority, and thorough-search prompts."
          rows={breakdowns.by_ablation.rows}
          groupKey="tempter_ablation"
          order={ABLATION_ORDER}
          labelFormatter={labelForAblation}
          metricFocus={metricFocus}
        />
      </div>

      {/* Weakness Mechanism Breakdown */}
      <BreakdownSvgCard
        title="Weakness mechanism breakdown"
        subtitle="Escape and misuse rates across the built-in sandbox misconfiguration and leak mechanisms."
        rows={breakdowns.by_mechanism.rows}
        groupKey="mechanism"
        order={MECHANISM_ORDER}
        labelFormatter={labelForMechanism}
        metricFocus={metricFocus}
      />
    </div>
  );
}
