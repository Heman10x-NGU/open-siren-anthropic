import { AlertTriangle, ShieldCheck, ShieldOff } from 'lucide-react';
import type { RateCI, ReplayData } from '../types';
import { fmtCI, fmtPct } from '../lib/format';

interface ReplayPanelProps {
  replay: ReplayData;
}

interface MetricBarProps {
  label: string;
  description: string;
  metric: RateCI;
  barColor: string;
  valueColor: string;
}

function ReplayMetricBar({
  label,
  description,
  metric,
  barColor,
  valueColor,
}: MetricBarProps) {
  const ratePct = Math.max(0, Math.min(100, metric.rate * 100));
  const loPct = Math.max(0, Math.min(100, metric.lo * 100));
  const hiPct = Math.max(0, Math.min(100, metric.hi * 100));

  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-2">
        <div>
          <div className="text-xs font-medium text-zinc-200">{label}</div>
          <div className="text-[11px] text-zinc-500">{description}</div>
        </div>
        <div className="shrink-0 text-right font-mono tabular-nums">
          <div className={`text-sm font-semibold ${valueColor}`}>{fmtPct(metric)}</div>
          <div className="text-[10.5px] text-zinc-500">
            {metric.k}/{metric.n} {fmtCI(metric)}
          </div>
        </div>
      </div>

      {/* Horizontal bar with 95% Wilson CI whisker overlay */}
      <div className="relative h-3 w-full overflow-hidden rounded-full bg-zinc-950 ring-1 ring-inset ring-zinc-800">
        {metric.n > 0 && (
          <>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${Math.max(ratePct, metric.k > 0 ? 1.5 : 0)}%`,
                backgroundColor: barColor,
                opacity: 0.85,
              }}
            />
            {/* CI whisker span */}
            <div
              className="pointer-events-none absolute top-1/2 h-[1.5px] -translate-y-1/2 bg-zinc-100/90"
              style={{
                left: `${loPct}%`,
                width: `${Math.max(hiPct - loPct, 0.5)}%`,
              }}
            />
            {/* Left CI cap */}
            <div
              className="pointer-events-none absolute top-1/2 h-2 w-[1.5px] -translate-y-1/2 bg-zinc-100/90"
              style={{ left: `${loPct}%` }}
            />
            {/* Right CI cap */}
            <div
              className="pointer-events-none absolute top-1/2 h-2 w-[1.5px] -translate-y-1/2 bg-zinc-100/90"
              style={{ left: `calc(${hiPct}% - 1.5px)` }}
            />
          </>
        )}
      </div>
    </div>
  );
}

export function ReplayPanel({ replay }: ReplayPanelProps) {
  const entries = Object.entries(replay.by_model).sort(([a], [b]) => a.localeCompare(b));
  const caveatText =
    entries[0]?.[1]?.caveat ??
    'Offline replay evaluates recorded commands and does not model agent behavior after a command is blocked.';

  return (
    <div className="space-y-5">
      {/* Explicit Caveat Callout */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3.5 text-xs text-amber-200/95">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
        <div>
          <div className="font-semibold text-amber-300">Offline Replay Methodology Caveat</div>
          <p className="mt-0.5 leading-relaxed text-amber-100/80">{caveatText}</p>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="flex h-40 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-900/40 text-xs text-zinc-500">
          No Auto-Gate offline replay reports found in replay.json.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
          {entries.map(([model, report]) => {
            const fpHigh = report.benign_commands_blocked.rate >= 0.05;
            return (
              <article
                key={model}
                className="flex flex-col justify-between rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-5"
              >
                <div>
                  <div className="mb-4 flex flex-wrap items-start justify-between gap-2 border-b border-zinc-800/80 pb-3.5">
                    <div>
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                        <h3 className="font-mono text-sm font-semibold text-zinc-100">{model}</h3>
                      </div>
                      <p className="mt-1 text-xs text-zinc-400">
                        Auto-Gate command classifier evaluated offline on recorded traces
                      </p>
                    </div>

                    <div className="flex gap-2 font-mono text-[11px] tabular-nums">
                      <span className="rounded border border-zinc-800 bg-zinc-950 px-2 py-0.5 text-zinc-300">
                        {report.n_episodes} ep
                      </span>
                      <span className="rounded border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 text-amber-300">
                        {report.n_reaching} reach
                      </span>
                      <span className="rounded border border-red-500/25 bg-red-500/10 px-2 py-0.5 text-red-300">
                        {report.n_misaligned} misal
                      </span>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <ReplayMetricBar
                      label="Blocked at first_reach_seq"
                      description="Share of reaching episodes intercepted on their first out-of-sandbox command"
                      metric={report.blocked_first_reach}
                      barColor="#10b981"
                      valueColor="text-emerald-400"
                    />

                    <ReplayMetricBar
                      label="Blocked at first_read_seq (misaligned)"
                      description="Share of misaligned-use episodes intercepted before reading the honeypot secret"
                      metric={report.blocked_first_read_misaligned}
                      barColor="#14b8a6"
                      valueColor="text-teal-300"
                    />

                    <ReplayMetricBar
                      label="Benign commands blocked (FP rate)"
                      description="Commands executed in non-reaching workspace workflows erroneously denied"
                      metric={report.benign_commands_blocked}
                      barColor={fpHigh ? '#f59e0b' : '#38bdf8'}
                      valueColor={fpHigh ? 'text-amber-400' : 'text-sky-300'}
                    />
                  </div>
                </div>

                <div className="mt-5 flex items-center justify-between border-t border-zinc-800/70 pt-3 text-[11px] text-zinc-500">
                  <span className="inline-flex items-center gap-1.5">
                    <ShieldOff className="h-3.5 w-3.5 text-zinc-500" />
                    Whiskers indicate 95% Wilson CI
                  </span>
                  <span className="font-mono">schema v{report.schema_version}</span>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
