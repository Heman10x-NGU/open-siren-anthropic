import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, ExternalLink } from 'lucide-react';
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

  const SortIcon = ({ col }: { col: SortKey }) => {
    if (sortKey !== col) {
      return <ArrowUpDown className="h-3 w-3 text-zinc-600" />;
    }
    return sortDir === 'asc' ? (
      <ArrowUp className="h-3 w-3 text-amber-400" />
    ) : (
      <ArrowDown className="h-3 w-3 text-amber-400" />
    );
  };

  const headerBtn = (col: SortKey, label: string, align: 'left' | 'right' = 'right') => (
    <button
      type="button"
      onClick={() => toggleSort(col)}
      className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-400 transition-colors hover:text-zinc-100 ${
        align === 'right' ? 'justify-end' : 'justify-start'
      }`}
    >
      <span>{label}</span>
      <SortIcon col={col} />
    </button>
  );

  return (
    <section className="rounded-xl border border-zinc-800/90 bg-zinc-900/60">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/80 px-5 py-3.5">
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-zinc-100">
            Leaderboard Matrix
          </h2>
          <p className="mt-0.5 text-xs text-zinc-400">
            Rates exclude errored episodes. Bounds are 95% Wilson score intervals. Click any column header to sort.
          </p>
        </div>
        <span className="font-mono text-xs text-zinc-500 tabular-nums">
          {sortedRows.length} row{sortedRows.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-950/60">
              <th className="px-4 py-3">{headerBtn('model', 'Model', 'left')}</th>
              <th className="px-4 py-3">{headerBtn('mitigation', 'Mitigation Set', 'left')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('n_episodes', 'N (err)')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('reached', 'Reached % [CI]')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('used', 'Used %')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('misaligned', 'Misaligned %')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('eval_aware', 'Eval-Aware %')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('reported', 'Reported %')}</th>
              <th className="px-3 py-3 text-right">{headerBtn('feasible', 'Feasible Solved %')}</th>
              <th className="px-4 py-3 text-right">
                {headerBtn('reduction', 'Reach Red. vs none')}
              </th>
              {onInspectModelMitigation && <th className="px-3 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Traces</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/70">
            {sortedRows.length === 0 ? (
              <tr>
                <td
                  colSpan={onInspectModelMitigation ? 11 : 10}
                  className="px-4 py-10 text-center text-zinc-500"
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
                    className="transition-colors hover:bg-zinc-800/35"
                  >
                    <td className="whitespace-nowrap px-4 py-3">
                      <div className="font-medium text-zinc-100">{model}</div>
                      {backends.length > 0 && (
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {backends.map((b) => (
                            <span
                              key={b}
                              className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.2 font-mono text-[10px] text-zinc-400"
                            >
                              {b}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] ${
                          mit === 'none'
                            ? 'border-zinc-700 bg-zinc-800/70 text-zinc-300'
                            : mit === 'all'
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                              : 'border-sky-500/25 bg-sky-500/10 text-sky-300'
                        }`}
                      >
                        {mit}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-zinc-300 tabular-nums">
                      {row.n_episodes}{' '}
                      <span className={row.n_errors > 0 ? 'text-red-400' : 'text-zinc-500'}>
                        ({row.n_errors})
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span className="font-semibold text-amber-400">
                        {fmtPct(row.reached)}
                      </span>
                      <span className="ml-1.5 text-[11px] text-zinc-500">
                        {fmtCI(row.reached)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          row.used.rate > 0 ? 'font-medium text-orange-400' : 'text-zinc-400'
                        }
                      >
                        {fmtPct(row.used)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          row.misaligned.rate > 0
                            ? 'rounded bg-red-500/15 px-1.5 py-0.5 font-semibold text-red-400'
                            : 'text-zinc-400'
                        }
                      >
                        {fmtPct(row.misaligned)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-sky-300/90 tabular-nums">
                      {fmtPct(row.eval_aware)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono tabular-nums">
                      <span
                        className={
                          row.reported.rate > 0
                            ? 'font-medium text-emerald-400'
                            : 'text-zinc-500'
                        }
                      >
                        {fmtPct(row.reported)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-right font-mono text-zinc-200 tabular-nums">
                      {fmtPct(row.task_completed_feasible)}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right font-mono tabular-nums">
                      {reduction === null ? (
                        <span className="text-zinc-600">—</span>
                      ) : (
                        <span
                          className={`rounded px-1.5 py-0.5 font-medium ${
                            reduction > 0
                              ? 'bg-emerald-500/15 text-emerald-400'
                              : reduction < 0
                                ? 'bg-red-500/15 text-red-400'
                                : 'text-zinc-400'
                          }`}
                        >
                          {fmtReduction(reduction)}
                        </span>
                      )}
                    </td>
                    {onInspectModelMitigation && (
                      <td className="whitespace-nowrap px-3 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => onInspectModelMitigation(model, mit)}
                          className="inline-flex items-center gap-1 rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-100"
                          title={`Explore traces for ${model} (${mit})`}
                        >
                          <span>Traces</span>
                          <ExternalLink className="h-3 w-3" />
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
