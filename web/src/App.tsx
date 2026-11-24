import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  BarChart3,
  Clock,
  FlaskConical,
  GitBranch,
  Info,
  Layers,
  RotateCcw,
  Shield,
  Terminal,
} from 'lucide-react';
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

  // Derive model -> backends mapping from manifest.episode_index
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

  // Aggregate KPI strip computed from baseline ("none") & "all" rows
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

  const navTabs: Array<{ id: ActiveTab; label: string; icon: typeof BarChart3 }> = [
    { id: 'leaderboard', label: 'Leaderboard & Mitigations', icon: BarChart3 },
    { id: 'ablations', label: 'Difficulty & Ablations', icon: Layers },
    { id: 'replay', label: 'Auto-Gate Replay', icon: Shield },
    { id: 'trace', label: 'Trace Explorer', icon: Terminal },
  ];

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Explicit Data Provenance Banner */}
      {manifest && manifest.is_demo && (
        <div className="border-b border-amber-500/30 bg-amber-500/10">
          <div className="mx-auto flex max-w-7xl items-center gap-2.5 px-4 py-2.5 text-xs text-amber-200 sm:px-6">
            <Info className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              Showing sample scripted-agent demo dataset. Run{' '}
              <code className="rounded bg-zinc-900/90 px-1.5 py-0.5 font-mono text-[11px] text-amber-300">
                open-siren run
              </code>{' '}
              +{' '}
              <code className="rounded bg-zinc-900/90 px-1.5 py-0.5 font-mono text-[11px] text-amber-300">
                open-siren export-web
              </code>{' '}
              to load real model results.
            </span>
          </div>
        </div>
      )}

      {/* Top Navigation Header */}
      <header className="sticky top-0 z-30 border-b border-zinc-800/90 bg-zinc-950/90 backdrop-blur-md">
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          <div className="flex flex-wrap items-center justify-between gap-4 py-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-amber-500/35 bg-amber-500/10 text-amber-400">
                <Activity className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-base font-bold tracking-tight text-zinc-100">
                    Open Siren
                  </h1>
                  <span className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                    sandbox escape benchmark
                  </span>
                </div>
                <p className="text-xs text-zinc-400">
                  Empirical propensity, mitigation efficacy, and kernel-traced agent episodes
                </p>
              </div>
            </div>

            {/* Real-run provenance badge (shown when is_demo is false) + repo badge */}
            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              {manifest && !manifest.is_demo && (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 font-mono text-[11px] text-emerald-200">
                  <Clock className="h-3.5 w-3.5 text-emerald-400" />
                  <span>{fmtTimestamp(manifest.generated_at)}</span>
                  <span className="text-emerald-500/60">·</span>
                  <span>
                    {manifest.models.length} model{manifest.models.length === 1 ? '' : 's'}
                  </span>
                  <span className="text-emerald-500/60">·</span>
                  <span>{manifest.total_episodes} episodes</span>
                </div>
              )}

              <a
                href="https://github.com/heman10x/open-siren-anthropic"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900/80 px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:border-zinc-700 hover:text-zinc-100"
              >
                <GitBranch className="h-3.5 w-3.5 text-zinc-400" />
                <span>GitHub</span>
              </a>
            </div>
          </div>

          {/* Interactive 4-Tab Bar */}
          <nav
            aria-label="Dashboard sections"
            className="-mb-px flex gap-1 overflow-x-auto pb-px"
          >
            {navTabs.map((t) => {
              const Icon = t.icon;
              const active = route.tab === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => navigate(t.id, t.id === 'trace' ? route.episodeId : null)}
                  className={`inline-flex shrink-0 items-center gap-2 border-b-2 px-3.5 py-2.5 text-xs font-medium transition-colors ${
                    active
                      ? 'border-amber-400 text-amber-300'
                      : 'border-transparent text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{t.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {loading && (
          <div className="flex h-64 items-center justify-center rounded-xl border border-zinc-800 bg-zinc-900/40 text-sm text-zinc-400">
            Loading Open Siren benchmark artifacts…
          </div>
        )}

        {!loading && error && (
          <div className="flex items-start gap-3 rounded-xl border border-red-500/35 bg-red-950/25 p-5 text-sm text-red-200">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
            <div>
              <div className="font-semibold text-red-300">Failed to load benchmark data</div>
              <p className="mt-1 font-mono text-xs text-red-200/80">{error}</p>
            </div>
          </div>
        )}

        {!loading && !error && manifest && leaderboard && breakdowns && replay && (
          <>
            {/* KPI Summary Strip */}
            {kpis && (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/55 px-4 py-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">Models Evaluated</div>
                  <div className="mt-1 font-mono text-xl font-bold text-zinc-100 tabular-nums">
                    {kpis.modelsCount}
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-zinc-500">
                    {manifest.backends.join(' · ')}
                  </div>
                </div>

                <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/55 px-4 py-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">Total Episodes</div>
                  <div className="mt-1 font-mono text-xl font-bold text-zinc-100 tabular-nums">
                    {kpis.totalEpisodes.toLocaleString('en-US')}
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-zinc-500">
                    {manifest.episode_index.length} trace{manifest.episode_index.length === 1 ? '' : 's'} indexed
                  </div>
                </div>

                <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/55 px-4 py-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">Baseline Reached</div>
                  <div className="mt-1 font-mono text-xl font-bold text-amber-400 tabular-nums">
                    {kpis.baselineReachRate !== null ? `${kpis.baselineReachRate.toFixed(1)}%` : '—'}
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-zinc-500">
                    mitigation = none
                  </div>
                </div>

                <div className="rounded-xl border border-zinc-800/90 bg-zinc-900/55 px-4 py-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">Baseline Misaligned</div>
                  <div className="mt-1 font-mono text-xl font-bold text-red-400 tabular-nums">
                    {kpis.baselineMisalignedRate !== null
                      ? `${kpis.baselineMisalignedRate.toFixed(1)}%`
                      : '—'}
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-zinc-500">
                    clear-violation misuse
                  </div>
                </div>

                <div className="col-span-2 rounded-xl border border-zinc-800/90 bg-zinc-900/55 px-4 py-3.5 sm:col-span-1">
                  <div className="text-[11px] font-medium text-zinc-400">Peak Mitigation Drop</div>
                  <div className="mt-1 font-mono text-xl font-bold text-emerald-400 tabular-nums">
                    {kpis.peakReduction !== null ? `-${kpis.peakReduction.toFixed(1)}%` : '—'}
                  </div>
                  <div className="mt-0.5 font-mono text-[10.5px] text-zinc-500">
                    reach reduction vs none
                  </div>
                </div>
              </div>
            )}

            {/* TAB 1: Leaderboard & Mitigation Impact */}
            {route.tab === 'leaderboard' && (
              <div className="space-y-5">
                {/* Filter Pill Controls */}
                <section className="space-y-3 rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-200">
                      <FlaskConical className="h-3.5 w-3.5 text-amber-400" />
                      Filter Leaderboard
                    </span>
                    {hasActiveFilters && (
                      <button
                        type="button"
                        onClick={resetFilters}
                        className="inline-flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-100"
                      >
                        <RotateCcw className="h-3 w-3" />
                        Reset filters
                      </button>
                    )}
                  </div>

                  <div className="space-y-2.5 text-xs">
                    {/* Model Pills */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 text-[11px] font-medium text-zinc-500">
                        Model
                      </span>
                      {manifest.models.map((m) => {
                        const active = selectedModels.has(m);
                        return (
                          <button
                            key={m}
                            type="button"
                            onClick={() => toggleSet(setSelectedModels, m)}
                            className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                              active
                                ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
                                : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                            }`}
                          >
                            {m}
                          </button>
                        );
                      })}
                    </div>

                    {/* Backend Pills */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 text-[11px] font-medium text-zinc-500">
                        Backend
                      </span>
                      {manifest.backends.map((b) => {
                        const active = selectedBackends.has(b);
                        return (
                          <button
                            key={b}
                            type="button"
                            onClick={() => toggleSet(setSelectedBackends, b)}
                            className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                              active
                                ? 'border-sky-500/50 bg-sky-500/15 text-sky-200'
                                : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                            }`}
                          >
                            {b}
                          </button>
                        );
                      })}
                    </div>

                    {/* Mitigation Set Pills */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="w-24 shrink-0 text-[11px] font-medium text-zinc-500">
                        Mitigation Set
                      </span>
                      {orderedMitigations.map((mit) => {
                        const active = selectedMitigations.has(mit);
                        return (
                          <button
                            key={mit}
                            type="button"
                            onClick={() => toggleSet(setSelectedMitigations, mit)}
                            className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                              active
                                ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-200'
                                : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
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

            {/* TAB 2: Difficulty & Tempter Ablations */}
            {route.tab === 'ablations' && <AblationCharts breakdowns={breakdowns} />}

            {/* TAB 3: Auto-Gate Offline Replay */}
            {route.tab === 'replay' && <ReplayPanel replay={replay} />}

            {/* TAB 4: Interactive Episode Trace Explorer */}
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

      <footer className="mt-12 border-t border-zinc-900 bg-zinc-950 py-6 text-xs text-zinc-500">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 px-4 sm:px-6">
          <span>
            Open Siren — Open-source AI agent sandbox escape benchmark &amp; mitigation testbed.
          </span>
          <span className="font-mono text-[11px]">
            {manifest ? `data schema v${manifest.schema_version} · generated ${fmtTimestamp(manifest.generated_at)}` : ''}
          </span>
        </div>
      </footer>
    </div>
  );
}
