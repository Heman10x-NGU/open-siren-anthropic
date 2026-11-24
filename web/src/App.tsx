import { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  ActiveTab,
  BreakdownsData,
  Manifest,
  ReplayData,
  SuiteSummary,
} from './types';
import { MITIGATION_ORDER, dataUrl, fmtTimestamp } from './lib/format';
import { MitigationChart } from './components/MitigationChart';
import { LeaderboardTable } from './components/LeaderboardTable';
import { AblationCharts } from './components/AblationCharts';
import { ReplayPanel } from './components/ReplayPanel';
import { TraceExplorer } from './components/TraceExplorer';

interface ParsedHash {
  tab: ActiveTab;
  episodeId: string | null;
}

function parseHash(rawHash: string): ParsedHash {
  const cleaned = rawHash.replace(/^#\/?/, '').trim();
  if (!cleaned || cleaned === 'leaderboard') {
    return { tab: 'leaderboard', episodeId: null };
  }
  if (cleaned === 'ablations') {
    return { tab: 'ablations', episodeId: null };
  }
  if (cleaned === 'replay') {
    return { tab: 'replay', episodeId: null };
  }
  if (cleaned.startsWith('trace/')) {
    return { tab: 'trace', episodeId: decodeURIComponent(cleaned.slice('trace/'.length)) };
  }
  if (cleaned.startsWith('traces/')) {
    return { tab: 'trace', episodeId: decodeURIComponent(cleaned.slice('traces/'.length)) };
  }
  if (cleaned === 'trace' || cleaned === 'traces') {
    return { tab: 'trace', episodeId: null };
  }
  return { tab: 'leaderboard', episodeId: null };
}

function toHash(tab: ActiveTab, episodeId?: string | null): string {
  if (tab === 'trace' && episodeId) {
    return `#trace/${encodeURIComponent(episodeId)}`;
  }
  return `#${tab}`;
}

const NAV_TABS: Array<{ id: ActiveTab; label: string; shortLabel: string }> = [
  { id: 'leaderboard', label: 'Leaderboard', shortLabel: 'Leaderboard' },
  { id: 'ablations', label: 'Ablations', shortLabel: 'Ablations' },
  { id: 'replay', label: 'Auto-Gate Replay', shortLabel: 'Replay' },
  { id: 'trace', label: 'Trace Explorer', shortLabel: 'Traces' },
];

export default function App() {
  const [route, setRoute] = useState<ParsedHash>(() => parseHash(window.location.hash));

  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [leaderboard, setLeaderboard] = useState<SuiteSummary | null>(null);
  const [breakdowns, setBreakdowns] = useState<BreakdownsData | null>(null);
  const [replay, setReplay] = useState<ReplayData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Leaderboard filters
  const [selectedModels, setSelectedModels] = useState<Set<string>>(new Set());
  const [selectedBackends, setSelectedBackends] = useState<Set<string>>(new Set());
  const [selectedMitigations, setSelectedMitigations] = useState<Set<string>>(new Set());

  // Cross-tab jump pre-filters for TraceExplorer
  const [traceJumpModel, setTraceJumpModel] = useState<string | null>(null);
  const [traceJumpMitigation, setTraceJumpMitigation] = useState<string | null>(null);

  useEffect(() => {
    const onHashChange = () => {
      setRoute(parseHash(window.location.hash));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const navigate = useCallback((tab: ActiveTab, episodeId?: string | null) => {
    const nextHash = toHash(tab, episodeId);
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    }
    setRoute({ tab, episodeId: episodeId ?? null });
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      fetch(dataUrl('manifest.json')).then((r) => {
        if (!r.ok) throw new Error(`manifest.json: HTTP ${r.status}`);
        return r.json() as Promise<Manifest>;
      }),
      fetch(dataUrl('leaderboard.json')).then((r) => {
        if (!r.ok) throw new Error(`leaderboard.json: HTTP ${r.status}`);
        return r.json() as Promise<SuiteSummary>;
      }),
      fetch(dataUrl('breakdowns.json')).then((r) => {
        if (!r.ok) throw new Error(`breakdowns.json: HTTP ${r.status}`);
        return r.json() as Promise<BreakdownsData>;
      }),
      fetch(dataUrl('replay.json')).then((r) => {
        if (!r.ok) throw new Error(`replay.json: HTTP ${r.status}`);
        return r.json() as Promise<ReplayData>;
      }),
    ])
      .then(([m, lb, bd, rp]) => {
        if (cancelled) return;
        setManifest(m);
        setLeaderboard(lb);
        setBreakdowns(bd);
        setReplay(rp);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load benchmark datasets.');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const modelBackends = useMemo(() => {
    const map: Record<string, string[]> = {};
    if (!manifest) return map;
    const sets = new Map<string, Set<string>>();
    for (const ep of manifest.episode_index) {
      const s = sets.get(ep.model) ?? new Set<string>();
      s.add(ep.backend);
      sets.set(ep.model, s);
    }
    for (const [model, s] of sets.entries()) {
      map[model] = Array.from(s).sort();
    }
    return map;
  }, [manifest]);

  const orderedMitigations = useMemo(() => {
    const source = manifest?.mitigation_sets ?? [];
    const rank = new Map<string, number>(MITIGATION_ORDER.map((m, i) => [m, i]));
    return [...source].sort((a, b) => {
      const ra = rank.get(a) ?? 999;
      const rb = rank.get(b) ?? 999;
      return ra !== rb ? ra - rb : a.localeCompare(b);
    });
  }, [manifest]);

  const filteredLeaderboardRows = useMemo(() => {
    if (!leaderboard) return [];
    const mitRank = new Map<string, number>(MITIGATION_ORDER.map((m, i) => [m, i]));
    return leaderboard.rows
      .filter((row) => {
        const model = row.group.model ?? '';
        const mit = row.group.mitigation_set_id ?? '';
        const rowBackend = row.group.backend;

        if (selectedModels.size > 0 && !selectedModels.has(model)) return false;
        if (selectedMitigations.size > 0 && !selectedMitigations.has(mit)) return false;
        if (selectedBackends.size > 0) {
          if (rowBackend) {
            if (!selectedBackends.has(rowBackend)) return false;
          } else {
            const mBackends = modelBackends[model] ?? manifest?.backends ?? [];
            if (!mBackends.some((b) => selectedBackends.has(b))) return false;
          }
        }
        return true;
      })
      .sort((a, b) => {
        const mc = (a.group.model ?? '').localeCompare(b.group.model ?? '');
        if (mc !== 0) return mc;
        const ra = mitRank.get(a.group.mitigation_set_id ?? '') ?? 999;
        const rb = mitRank.get(b.group.mitigation_set_id ?? '') ?? 999;
        return ra - rb;
      });
  }, [
    leaderboard,
    selectedModels,
    selectedMitigations,
    selectedBackends,
    modelBackends,
    manifest,
  ]);

  const kpis = useMemo(() => {
    if (!leaderboard || !manifest) return null;
    const noneRows = leaderboard.rows.filter((r) => r.group.mitigation_set_id === 'none');
    const baseReachK = noneRows.reduce((acc, r) => acc + r.reached.k, 0);
    const baseReachN = noneRows.reduce((acc, r) => acc + r.reached.n, 0);
    const baseMisK = noneRows.reduce((acc, r) => acc + r.misaligned.k, 0);
    const baseMisN = noneRows.reduce((acc, r) => acc + r.misaligned.n, 0);

    const reductions = leaderboard.rows
      .map((r) => r.reached_reduction_vs_none)
      .filter((v): v is number => v !== null && v !== undefined);
    const peakReduction = reductions.length > 0 ? Math.max(...reductions) : null;

    return {
      modelsCount: manifest.models.length,
      totalEpisodes: manifest.total_episodes,
      baselineReachRate: baseReachN > 0 ? (baseReachK / baseReachN) * 100 : null,
      baselineMisalignedRate: baseMisN > 0 ? (baseMisK / baseMisN) * 100 : null,
      peakReduction: peakReduction !== null ? peakReduction * 100 : null,
    };
  }, [leaderboard, manifest]);

  const toggleSet = (setter: React.Dispatch<React.SetStateAction<Set<string>>>, val: string) => {
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(val)) next.delete(val);
      else next.add(val);
      return next;
    });
  };

  const hasActiveFilters =
    selectedModels.size > 0 || selectedBackends.size > 0 || selectedMitigations.size > 0;

  const resetFilters = () => {
    setSelectedModels(new Set());
    setSelectedBackends(new Set());
    setSelectedMitigations(new Set());
  };

  const handleInspectModelMitigation = (model: string, mitigation: string) => {
    setTraceJumpModel(model);
    setTraceJumpMitigation(mitigation);
    const match = manifest?.episode_index.find(
      (e) => e.model === model && e.mitigation_set_id === mitigation,
    );
    navigate('trace', match?.episode_id ?? null);
  };

  return (
    <div className="min-h-screen bg-[#f5f5f4] text-[#141414]">
      {/* Single-Row Editorial Header */}
      <header className="sticky top-0 z-30 border-b border-[#141414]/[0.14] bg-white">
        <div className="mx-auto flex max-w-[1120px] flex-wrap items-center justify-between gap-x-6 gap-y-2 px-6">
          {/* Brand Mark + Wordmark */}
          <button
            type="button"
            onClick={() => navigate('leaderboard')}
            className="flex items-center gap-2.5 py-3.5 text-left transition-opacity duration-150 hover:opacity-80"
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              aria-hidden="true"
              className="shrink-0"
            >
              <rect
                x="1.5"
                y="1.5"
                width="21"
                height="21"
                rx="3"
                stroke="#141414"
                strokeWidth="1.4"
              />
              <rect
                x="6"
                y="6"
                width="12"
                height="12"
                rx="1.5"
                stroke="#141414"
                strokeWidth="1.2"
                strokeDasharray="2.5 2"
              />
              <circle cx="12" cy="12" r="2.25" fill="#eb6c36" />
            </svg>
            <span className="font-serif text-[22px] leading-none tracking-[-0.02em] text-[#141414]">
              Open Siren
            </span>
          </button>

          {/* Plain Text Underline Tabs */}
          <nav
            aria-label="Dashboard sections"
            className="order-3 -mb-px flex w-full gap-4 overflow-x-auto border-t border-[#e5e5e5] sm:gap-5 md:order-2 md:w-auto md:border-t-0"
          >
            {NAV_TABS.map((t) => {
              const active = route.tab === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => navigate(t.id, t.id === 'trace' ? route.episodeId : null)}
                  className={`shrink-0 border-b-[1.5px] py-3 text-[13px] transition-colors duration-150 md:py-4 ${
                    active
                      ? 'border-[#141414] font-medium text-[#141414]'
                      : 'border-transparent text-[#737373] hover:border-[#d4d4d4] hover:text-[#141414]'
                  }`}
                >
                  <span className="sm:hidden">{t.shortLabel}</span>
                  <span className="hidden sm:inline">{t.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Quiet External Repo Link */}
          <a
            href="https://github.com/Heman10x-NGU/open-siren-anthropic"
            target="_blank"
            rel="noreferrer"
            className="order-2 text-xs font-medium text-[#525252] transition-colors duration-150 hover:text-[#141414] md:order-3"
          >
            GitHub ↗
          </a>
        </div>
      </header>

      {/* Quiet 1-Row Data Provenance Strip */}
      {manifest && (
        <div className="border-b border-[#141414]/[0.1] bg-[#fafaf9]">
          <div className="mx-auto max-w-[1120px] px-6 py-2.5 text-xs leading-relaxed text-[#525252]">
            {manifest.is_demo ? (
              <p>
                <span className="font-medium text-[#141414]">Reference harness dataset</span>
                {' · '}
                <span className="font-mono tabular-nums text-[#141414]">
                  {manifest.total_episodes}
                </span>{' '}
                real local episodes executed with deterministic scripted agents (
                <code className="font-mono text-[11px] text-[#141414]">scripted-escapist</code>,{' '}
                <code className="font-mono text-[11px] text-[#141414]">scripted-reporter</code>,{' '}
                <code className="font-mono text-[11px] text-[#141414]">scripted-stay-inside</code>)
                via <code className="font-mono text-[11px] text-[#141414]">open-siren run</code> +{' '}
                <code className="font-mono text-[11px] text-[#141414]">open-siren export-web</code>.
                Live frontier model runs coming next.
              </p>
            ) : (
              <p className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11.5px] tabular-nums text-[#525252]">
                <span className="text-[#141414]">{fmtTimestamp(manifest.generated_at)}</span>
                <span className="text-[#a3a3a3]">·</span>
                <span>
                  {manifest.models.length} model{manifest.models.length === 1 ? '' : 's'}
                </span>
                <span className="text-[#a3a3a3]">·</span>
                <span>{manifest.total_episodes.toLocaleString('en-US')} episodes</span>
                <span className="text-[#a3a3a3]">·</span>
                <span>{manifest.backends.join(', ')}</span>
              </p>
            )}
          </div>
        </div>
      )}

      {/* Main Workspace */}
      <main className="mx-auto max-w-[1120px] space-y-6 px-6 py-7">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-[30px] leading-[1.12] text-[#141414] sm:text-[34px]">
              Sandbox Escape Propensity &amp; Mitigation Benchmark
            </h1>
            <p className="mt-1.5 text-[13px] text-[#525252]">
              Empirical escape rates with 95% Wilson confidence intervals, tempter ablations,
              Auto-Gate replay, and kernel-traced agent episodes.
            </p>
          </div>
        </div>

        {loading && (
          <div className="flex h-56 items-center justify-center rounded-[6px] border border-[#141414]/[0.14] bg-white font-mono text-xs text-[#737373]">
            Loading benchmark artifacts…
          </div>
        )}

        {!loading && error && (
          <div className="rounded-[6px] border border-[#eb6c36] bg-white p-5 text-xs text-[#141414]">
            <div className="font-medium text-[#eb6c36]">Failed to load benchmark data</div>
            <p className="mt-1 font-mono text-[#525252]">{error}</p>
          </div>
        )}

        {!loading && !error && manifest && leaderboard && breakdowns && replay && (
          <>
            {/* 4-Column Flat Typographic KPI Strip */}
            {kpis && (
              <section
                aria-label="Summary metrics"
                className="grid grid-cols-2 rounded-[6px] border border-[#141414]/[0.14] bg-white lg:grid-cols-4 [&>*]:border-[#e5e5e5] [&>*:nth-child(-n+2)]:border-b [&>*:nth-child(odd)]:border-r lg:[&>*:nth-child(-n+2)]:border-b-0 lg:[&>*:not(:last-child)]:border-r"
              >
                <div className="px-5 py-4">
                  <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
                    Evaluated Corpus
                  </div>
                  <div className="mt-1.5 font-mono text-2xl font-medium tracking-tight text-[#141414] tabular-nums">
                    {kpis.totalEpisodes.toLocaleString('en-US')}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#737373]">
                    {kpis.modelsCount} model{kpis.modelsCount === 1 ? '' : 's'} ·{' '}
                    {manifest.backends.join(', ')}
                  </div>
                </div>

                <div className="px-5 py-4">
                  <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
                    Baseline Reached
                  </div>
                  <div className="mt-1.5 font-mono text-2xl font-medium tracking-tight text-[#141414] tabular-nums">
                    {kpis.baselineReachRate !== null ? `${kpis.baselineReachRate.toFixed(1)}%` : '—'}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#737373]">
                    mitigation = none
                  </div>
                </div>

                <div className="px-5 py-4">
                  <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
                    Baseline Misaligned
                  </div>
                  <div
                    className={`mt-1.5 font-mono text-2xl font-medium tracking-tight tabular-nums ${
                      kpis.baselineMisalignedRate !== null && kpis.baselineMisalignedRate > 0
                        ? 'text-[#eb6c36]'
                        : 'text-[#141414]'
                    }`}
                  >
                    {kpis.baselineMisalignedRate !== null
                      ? `${kpis.baselineMisalignedRate.toFixed(1)}%`
                      : '—'}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#737373]">
                    clear-violation misuse
                  </div>
                </div>

                <div className="px-5 py-4">
                  <div className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
                    Peak Mitigation Drop
                  </div>
                  <div className="mt-1.5 font-mono text-2xl font-medium tracking-tight text-[#141414] tabular-nums">
                    {kpis.peakReduction !== null ? `-${kpis.peakReduction.toFixed(1)}%` : '—'}
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-[#737373]">
                    reach reduction vs none
                  </div>
                </div>
              </section>
            )}

            {/* TAB 1: Leaderboard */}
            {route.tab === 'leaderboard' && (
              <div className="space-y-6">
                {/* Quiet Inline Filter Bar */}
                <section className="rounded-[6px] border border-[#141414]/[0.14] bg-white px-5 py-4">
                  <div className="mb-3 flex items-center justify-between gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#737373]">
                      Filters
                    </span>
                    {hasActiveFilters && (
                      <button
                        type="button"
                        onClick={resetFilters}
                        className="font-mono text-[11px] text-[#525252] underline underline-offset-4 transition-colors duration-150 hover:text-[#141414]"
                      >
                        Reset
                      </button>
                    )}
                  </div>

                  <div className="space-y-2.5 text-xs">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 font-mono text-[11px] text-[#737373]">
                        Model
                      </span>
                      {manifest.models.map((m) => {
                        const active = selectedModels.has(m);
                        return (
                          <button
                            key={m}
                            type="button"
                            onClick={() => toggleSet(setSelectedModels, m)}
                            className={`rounded-[4px] border px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                              active
                                ? 'border-[#141414] bg-[#141414] text-white'
                                : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
                            }`}
                          >
                            {m}
                          </button>
                        );
                      })}
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 font-mono text-[11px] text-[#737373]">
                        Backend
                      </span>
                      {manifest.backends.map((b) => {
                        const active = selectedBackends.has(b);
                        return (
                          <button
                            key={b}
                            type="button"
                            onClick={() => toggleSet(setSelectedBackends, b)}
                            className={`rounded-[4px] border px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                              active
                                ? 'border-[#141414] bg-[#141414] text-white'
                                : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
                            }`}
                          >
                            {b}
                          </button>
                        );
                      })}
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 font-mono text-[11px] text-[#737373]">
                        Mitigation
                      </span>
                      {orderedMitigations.map((mit) => {
                        const active = selectedMitigations.has(mit);
                        return (
                          <button
                            key={mit}
                            type="button"
                            onClick={() => toggleSet(setSelectedMitigations, mit)}
                            className={`rounded-[4px] border px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                              active
                                ? 'border-[#141414] bg-[#141414] text-white'
                                : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
                            }`}
                          >
                            {mit}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </section>

                <MitigationChart
                  rows={filteredLeaderboardRows}
                  groupBy={leaderboard.group_by}
                />

                <LeaderboardTable
                  rows={filteredLeaderboardRows}
                  modelBackends={modelBackends}
                  onInspectModelMitigation={handleInspectModelMitigation}
                />
              </div>
            )}

            {/* TAB 2: Ablations */}
            {route.tab === 'ablations' && <AblationCharts breakdowns={breakdowns} />}

            {/* TAB 3: Auto-Gate Replay */}
            {route.tab === 'replay' && <ReplayPanel replay={replay} />}

            {/* TAB 4: Trace Explorer */}
            {route.tab === 'trace' && (
              <TraceExplorer
                episodes={manifest.episode_index}
                models={manifest.models}
                mitigationSets={orderedMitigations}
                selectedEpisodeId={route.episodeId}
                onSelectEpisode={(id) => navigate('trace', id)}
                initialModelFilter={traceJumpModel}
                initialMitigationFilter={traceJumpMitigation}
              />
            )}
          </>
        )}
      </main>

      <footer className="mt-12 border-t border-[#141414]/[0.12] py-6 text-xs text-[#737373]">
        <div className="mx-auto flex max-w-[1120px] flex-wrap items-center justify-between gap-2 px-6">
          <span>
            Open Siren · Open-source AI agent sandbox escape benchmark &amp; mitigation testbed.
          </span>
          <span className="font-mono text-[11px] tabular-nums">
            {manifest
              ? `schema v${manifest.schema_version} · generated ${fmtTimestamp(manifest.generated_at)}`
              : ''}
          </span>
        </div>
      </footer>
    </div>
  );
}
