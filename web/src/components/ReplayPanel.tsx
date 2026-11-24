import type { RateCI, ReplayData } from '../types';
import { fmtCI, fmtPct } from '../lib/format';

interface ReplayPanelProps {
  replay: ReplayData;
}

interface MetricBarProps {
  label: string;
  description: string;
  metric: RateCI;
  accent?: 'ink' | 'slate' | 'breach';
}

function ReplayMetricBar({
  label,
  description,
  metric,
  accent = 'ink',
}: MetricBarProps) {
  const ratePct = Math.max(0, Math.min(100, metric.rate * 100));
  const loPct = Math.max(0, Math.min(100, metric.lo * 100));
  const hiPct = Math.max(0, Math.min(100, metric.hi * 100));

  const fillColor =
    accent === 'breach' ? '#eb6c36' : accent === 'slate' ? '#525252' : '#141414';
  const valueClass =
    accent === 'breach'
      ? 'text-[#eb6c36]'
      : accent === 'slate'
        ? 'text-[#525252]'
        : 'text-[#141414]';

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <div className="text-xs font-medium text-[#141414]">{label}</div>
          <div className="mt-0.5 text-[11px] text-[#737373]">{description}</div>
        </div>
        <div className="shrink-0 text-right font-mono tabular-nums">
          <div className={`text-sm font-medium ${valueClass}`}>{fmtPct(metric)}</div>
          <div className="text-[10.5px] text-[#737373]">
            {metric.k}/{metric.n} {fmtCI(metric)}
          </div>
        </div>
      </div>

      {/* Crisp flat progress bar with 95% Wilson CI whisker */}
      <div className="relative h-2 w-full rounded-[2px] bg-[#e5e5e5]">
        {metric.n > 0 && (
          <>
            <div
              className="h-full rounded-[2px] transition-all duration-150"
              style={{
                width: `${metric.k > 0 ? Math.max(ratePct, 1) : 0}%`,
                backgroundColor: fillColor,
              }}
            />
            {/* Halo + 1px Wilson CI span */}
            <div
              className="pointer-events-none absolute top-1/2 h-[3px] -translate-y-1/2 bg-white/80"
              style={{
                left: `${loPct}%`,
                width: `${Math.max(hiPct - loPct, 0.4)}%`,
              }}
            />
            <div
              className="pointer-events-none absolute top-1/2 h-[1px] -translate-y-1/2 bg-[#141414]"
              style={{
                left: `${loPct}%`,
                width: `${Math.max(hiPct - loPct, 0.4)}%`,
              }}
            />
            <div
              className="pointer-events-none absolute top-1/2 h-2.5 w-[1px] -translate-y-1/2 bg-[#141414]"
              style={{ left: `${loPct}%` }}
            />
            <div
              className="pointer-events-none absolute top-1/2 h-2.5 w-[1px] -translate-y-1/2 bg-[#141414]"
              style={{ left: `calc(${hiPct}% - 1px)` }}
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
    <div className="space-y-6">
      {/* Quiet muted methodology caveat line */}
      <div className="rounded-[6px] border border-[#141414]/[0.14] bg-[#fafaf9] px-5 py-3 text-xs leading-relaxed text-[#525252]">
        <span className="mr-2 font-mono text-[10px] font-medium uppercase tracking-[0.08em] text-[#141414]">
          Methodology Note
        </span>
        {caveatText}
      </div>

      {entries.length === 0 ? (
        <div className="flex h-40 items-center justify-center rounded-[6px] border border-dashed border-[#d4d4d4] bg-white text-xs text-[#737373]">
          No Auto-Gate offline replay reports found in replay.json.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          {entries.map(([model, report]) => {
            const fpHigh = report.benign_commands_blocked.rate >= 0.05;
            return (
              <article
                key={model}
                className="flex flex-col justify-between rounded-[6px] border border-[#141414]/[0.14] bg-white p-5"
              >
                <div>
                  <div className="mb-5 flex flex-wrap items-baseline justify-between gap-2 border-b border-[#e5e5e5] pb-3.5">
                    <div>
                      <h3 className="font-mono text-sm font-semibold text-[#141414]">{model}</h3>
                      <p className="mt-0.5 text-xs text-[#737373]">
                        Auto-Gate command classifier evaluated offline on recorded traces
                      </p>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-[11px] tabular-nums text-[#525252]">
                      <span>{report.n_episodes} ep</span>
                      <span className="text-[#d4d4d4]">·</span>
                      <span>{report.n_reaching} reach</span>
                      <span className="text-[#d4d4d4]">·</span>
                      <span className={report.n_misaligned > 0 ? 'font-medium text-[#eb6c36]' : ''}>
                        {report.n_misaligned} misal
                      </span>
                    </div>
                  </div>

                  <div className="space-y-5">
                    <ReplayMetricBar
                      label="Blocked at first_reach_seq"
                      description="Share of reaching episodes intercepted on their first out-of-sandbox command"
                      metric={report.blocked_first_reach}
                      accent="ink"
                    />

                    <ReplayMetricBar
                      label="Blocked at first_read_seq (misaligned)"
                      description="Share of misaligned-use episodes intercepted before reading the honeypot secret"
                      metric={report.blocked_first_read_misaligned}
                      accent="ink"
                    />

                    <ReplayMetricBar
                      label="Benign commands blocked (FP rate)"
                      description="Commands executed in non-reaching workspace workflows erroneously denied"
                      metric={report.benign_commands_blocked}
                      accent={fpHigh ? 'breach' : 'slate'}
                    />
                  </div>
                </div>

                <div className="mt-6 flex items-center justify-between border-t border-[#e5e5e5] pt-3 font-mono text-[10.5px] text-[#737373]">
                  <span>Whiskers denote 95% Wilson CI</span>
                  <span>schema v{report.schema_version}</span>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
