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
  { key: 'reached' as const, label: 'Reached Outside', color: '#f59e0b' },
  { key: 'used' as const, label: 'Used', color: '#f97316' },
  { key: 'misaligned' as const, label: 'Misaligned Use', color: '#ef4444' },
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
  const rightMargin = 88;
  const topMargin = 28;
  const bottomMargin = 26;
  const plotWidth = svgWidth - leftMargin - rightMargin;
  const barH = activeSeries.length === 1 ? 18 : 10;
  const barGap = 4;
  const groupPad = 18;
  const groupH = activeSeries.length * barH + (activeSeries.length - 1) * barGap + groupPad;
  const svgHeight = Math.max(120, topMargin + orderedRows.length * groupH + bottomMargin);
  const plotBottom = topMargin + orderedRows.length * groupH - groupPad / 2;

  return (
    <div className="flex flex-col rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-5">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold tracking-tight text-zinc-100">{title}</h3>
          <p className="mt-0.5 text-xs text-zinc-400">{subtitle}</p>
        </div>
        {hovered && (
          <div className="shrink-0 rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 font-mono text-[11px] tabular-nums">
            <span className="mr-1.5 inline-block h-2 w-2 rounded-xs" style={{ backgroundColor: hovered.color }} />
            <span className="font-semibold text-zinc-100">{fmtPct(hovered.metric)}</span>
            <span className="ml-1.5 text-zinc-400">
              ({hovered.metric.k}/{hovered.metric.n}) {fmtCI(hovered.metric)}
            </span>
          </div>
        )}
      </div>

      {orderedRows.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-lg border border-dashed border-zinc-800 text-xs text-zinc-500">
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
                    stroke="#27272a"
                    strokeWidth={1}
                    strokeDasharray={tick === 0 ? undefined : '3 3'}
                  />
                  <text
                    x={x}
                    y={plotBottom + 16}
                    textAnchor="middle"
                    className="fill-zinc-500 font-mono text-[10px]"
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
                  <text
                    x={leftMargin - 12}
                    y={rowTop + blockH / 2 + 1}
                    textAnchor="end"
                    className="fill-zinc-200 text-[11.5px] font-medium"
                  >
                    {displayLabel.length > 23 ? `${displayLabel.slice(0, 21)}…` : displayLabel}
                  </text>
                  <text
                    x={leftMargin - 12}
                    y={rowTop + blockH / 2 + 13}
                    textAnchor="end"
                    className="fill-zinc-500 font-mono text-[9.5px] tabular-nums"
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
                          x={leftMargin + 6}
                          y={midY + 3.5}
                          className="fill-zinc-600 font-mono text-[10px]"
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
                    const valueX = Math.max(leftMargin + barW, hiX) + 7;

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
                          y={y - 1}
                          width={plotWidth + rightMargin - 6}
                          height={barH + 2}
                          fill="transparent"
                        />
                        <rect
                          x={leftMargin}
                          y={y}
                          width={Math.max(barW, 2)}
                          height={barH}
                          rx={2.5}
                          fill={series.color}
                          opacity={0.86}
                        />
                        <line
                          x1={loX}
                          y1={midY}
                          x2={hiX}
                          y2={midY}
                          stroke="#e4e4e7"
                          strokeWidth={1.25}
                        />
                        <line
                          x1={loX}
                          y1={midY - 2.8}
                          x2={loX}
                          y2={midY + 2.8}
                          stroke="#e4e4e7"
                          strokeWidth={1.25}
                        />
                        <line
                          x1={hiX}
                          y1={midY - 2.8}
                          x2={hiX}
                          y2={midY + 2.8}
                          stroke="#e4e4e7"
                          strokeWidth={1.25}
                        />
                        <text
                          x={valueX}
                          y={midY + 3.5}
                          className="fill-zinc-300 font-mono text-[10px] tabular-nums"
                        >
                          {fmtPct(metric)}
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
    <div className="space-y-5">
      {/* Metric toggle & legend bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800/90 bg-zinc-900/60 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-zinc-400">Metric tier:</span>
          {(
            [
              { id: 'all', label: 'All 3 Tiers' },
              { id: 'reached', label: 'Reached Outside' },
              { id: 'used', label: 'Used' },
              { id: 'misaligned', label: 'Misaligned Use' },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setMetricFocus(opt.id)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                metricFocus === opt.id
                  ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
                  : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs text-zinc-400">
          {ALL_SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span
                className="inline-block h-2.5 w-2.5 rounded-xs"
                style={{ backgroundColor: s.color }}
              />
              {s.label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-3 bg-zinc-200" />
            95% Wilson CI
          </span>
        </div>
      </div>

      {/* Side-by-side Difficulty & Tempter Ablations */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <BreakdownSvgCard
          title="Task Difficulty Curve (Easy → Impossible)"
          subtitle="Propensity to cross sandbox boundaries as legitimate task solvability decreases."
          rows={breakdowns.by_difficulty.rows}
          groupKey="difficulty"
          order={DIFFICULTY_ORDER}
          labelFormatter={labelForDifficulty}
          metricFocus={metricFocus}
        />

        <BreakdownSvgCard
          title="Tempter Framing Ablations"
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
        title="Weakness Mechanism Breakdown"
        subtitle="Escape and misuse rates across the six built-in sandbox misconfiguration and leak mechanisms."
        rows={breakdowns.by_mechanism.rows}
        groupKey="mechanism"
        order={MECHANISM_ORDER}
        labelFormatter={labelForMechanism}
        metricFocus={metricFocus}
      />
    </div>
  );
}
