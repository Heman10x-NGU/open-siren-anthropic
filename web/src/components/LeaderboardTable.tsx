import { useMemo, useState } from 'react';
import type { SummaryRow } from '../types';
import { fmtCI, fmtPct, fmtReduction } from '../lib/format';

interface LeaderboardTableProps {
  rows: SummaryRow[];
  modelBackends: Record<string, string[]>;
  onInspectModelMitigation?: (model: string, mitigation: string) => void;
}

type SortKey =
  | 'model'
  | 'mitigation'
  | 'n_episodes'
  | 'reached'
  | 'used'
  | 'misaligned'
  | 'eval_aware'
  | 'reported'
  | 'feasible'
  | 'reduction';

export function LeaderboardTable({
  rows,
  modelBackends,
  onInspectModelMitigation,
}: LeaderboardTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('reached');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'model' || key === 'mitigation' ? 'asc' : 'desc');
    }
  };

  const sortedRows = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'model':
          cmp = (a.group.model ?? '').localeCompare(b.group.model ?? '');
          break;
        case 'mitigation':
          cmp = (a.group.mitigation_set_id ?? '').localeCompare(
            b.group.mitigation_set_id ?? '',
          );
          break;
        case 'n_episodes':
          cmp = a.n_episodes - b.n_episodes;
          break;
        case 'reached':
          cmp = a.reached.rate - b.reached.rate;
          break;
        case 'used':
          cmp = a.used.rate - b.used.rate;
          break;
        case 'misaligned':
          cmp = a.misaligned.rate - b.misaligned.rate;
          break;
        case 'eval_aware':
          cmp = a.eval_aware.rate - b.eval_aware.rate;
          break;
        case 'reported':
          cmp = a.reported.rate - b.reported.rate;
          break;
        case 'feasible':
          cmp = a.task_completed_feasible.rate - b.task_completed_feasible.rate;
          break;
        case 'reduction': {
          const av = a.reached_reduction_vs_none ?? -999;
          const bv = b.reached_reduction_vs_none ?? -999;
          cmp = av - bv;
          break;
        }
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortKey, sortDir]);

  const headerBtn = (col: SortKey, label: string, align: 'left' | 'right' = 'right') => {
    const active = sortKey === col;
    return (
      <button
        type="button"
        onClick={() => toggleSort(col)}
        className={`inline-flex items-center gap-1 font-mono text-[10px] font-medium uppercase tracking-[0.06em] transition-colors duration-150 ${
          active ? 'text-[#141414]' : 'text-[#737373] hover:text-[#141414]'
        } ${align === 'right' ? 'justify-end' : 'justify-start'}`}
      >
        <span>{label}</span>
        <span className={active ? 'text-[#141414]' : 'text-[#a3a3a3]'} aria-hidden="true">
          {active ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}
        </span>
      </button>
    );
  };

  return (
    <section className="rounded-[6px] border border-[#141414]/[0.14] bg-white">
      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-[#e5e5e5] px-5 py-4">
        <div>
          <h2 className="text-[22px] leading-tight text-[#141414]">Leaderboard matrix</h2>
          <p className="mt-1 text-xs text-[#737373]">
            Rates exclude errored episodes. Bounds are 95% Wilson score intervals. Select any column
            header to sort.
          </p>
        </div>
        <span className="font-mono text-[11px] text-[#737373] tabular-nums">
          {sortedRows.length} row{sortedRows.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-[#e5e5e5] bg-[#fafaf9]">
              <th className="px-5 py-3">{headerBtn('model', 'Model', 'left')}</th>
              <th className="px-4 py-3">{headerBtn('mitigation', 'Mitigation', 'left')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('n_episodes', 'N (err)')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('reached', 'Reached [CI]')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('used', 'Used')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('misaligned', 'Misaligned')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('eval_aware', 'Eval-Aware')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('reported', 'Reported')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('feasible', 'Solved')}</th>
              <th className="px-4 py-3 text-right">{headerBtn('reduction', 'vs None')}</th>
              {onInspectModelMitigation && (
                <th className="px-5 py-3 text-right font-mono text-[10px] font-medium uppercase tracking-[0.06em] text-[#737373]">
                  Trace
                </th>
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#e5e5e5]">
            {sortedRows.length === 0 ? (
              <tr>
                <td
                  colSpan={onInspectModelMitigation ? 11 : 10}
                  className="px-5 py-10 text-center text-xs text-[#737373]"
                >
                  No leaderboard rows match your active filters.
                </td>
              </tr>
            ) : (
              sortedRows.map((row, idx) => {
                const model = row.group.model ?? '—';
                const mit = row.group.mitigation_set_id ?? '—';
                const backends = row.group.backend
                  ? [row.group.backend]
                  : (modelBackends[model] ?? []);
                const reduction = row.reached_reduction_vs_none;

                return (
                  <tr
                    key={`${model}-${mit}-${idx}`}
                    className="transition-colors duration-150 hover:bg-[#fafaf9]"
                  >
                    <td className="whitespace-nowrap px-5 py-3">
                      <div className="font-mono text-[12px] font-medium text-[#141414]">
                        {model}
                      </div>
                      {backends.length > 0 && (
                        <div className="mt-0.5 font-mono text-[10px] text-[#737373]">
                          {backends.join(' · ')}
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`inline-flex items-center rounded-[4px] border px-2 py-0.5 font-mono text-[11px] ${
                          mit === 'all'
                            ? 'border-[#141414]/40 bg-white font-medium text-[#141414]'
                            : 'border-[#d4d4d4] bg-[#fafaf9] text-[#525252]'
                        }`}
                      >
                        {mit}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-[#525252] tabular-nums">
                      {row.n_episodes}{' '}
                      <span className={row.n_errors > 0 ? 'text-[#eb6c36]' : 'text-[#a3a3a3]'}>
                        ({row.n_errors})
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span className="font-medium text-[#141414]">{fmtPct(row.reached)}</span>
                      <span className="ml-1.5 text-[10.5px] text-[#737373]">
                        {fmtCI(row.reached)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span className={row.used.rate > 0 ? 'text-[#141414]' : 'text-[#a3a3a3]'}>
                        {fmtPct(row.used)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          row.misaligned.rate > 0
                            ? 'font-semibold text-[#eb6c36]'
                            : 'text-[#a3a3a3]'
                        }
                      >
                        {fmtPct(row.misaligned)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-[#525252] tabular-nums">
                      {fmtPct(row.eval_aware)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          row.reported.rate > 0 ? 'font-medium text-[#141414]' : 'text-[#a3a3a3]'
                        }
                      >
                        {fmtPct(row.reported)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-[#525252] tabular-nums">
                      {fmtPct(row.task_completed_feasible)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono tabular-nums">
                      {reduction === null ? (
                        <span className="text-[#a3a3a3]">—</span>
                      ) : (
                        <span
                          className={
                            reduction > 0
                              ? 'font-medium text-[#141414]'
                              : reduction < 0
                                ? 'font-medium text-[#eb6c36]'
                                : 'text-[#737373]'
                          }
                        >
                          {fmtReduction(reduction)}
                        </span>
                      )}
                    </td>
                    {onInspectModelMitigation && (
                      <td className="whitespace-nowrap px-5 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => onInspectModelMitigation(model, mit)}
                          className="text-xs font-medium text-[#525252] underline-offset-4 transition-colors duration-150 hover:text-[#141414] hover:underline"
                          title={`Explore traces for ${model} (${mit})`}
                        >
                          Inspect →
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
