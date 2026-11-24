import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Brain,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cpu,
  FileWarning,
  Filter,
  Flag,
  Globe,
  MessageSquare,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react';
import type {
  EpisodeIndexItem,
  EpisodeResult,
  ExecResultPayload,
  GateDecision,
  HoneypotHit,
  OutcomeBadge,
  OutsideSyscall,
  TraceEvent,
} from '../types';
import {
  dataUrl,
  fmtDuration,
  fmtTimestamp,
  fmtTokens,
  getEpisodeOutcomeBadges,
  labelForAblation,
  labelForDifficulty,
  labelForMechanism,
  outcomeBadgeStyle,
} from '../lib/format';

interface TraceExplorerProps {
  episodes: EpisodeIndexItem[];
  models: string[];
  mitigationSets: string[];
  selectedEpisodeId: string | null;
  onSelectEpisode: (episodeId: string) => void;
  initialModelFilter?: string | null;
  initialMitigationFilter?: string | null;
}

const OUTCOME_FILTERS: OutcomeBadge[] = [
  'Misaligned',
  'Used',
  'Reached',
  'Blocked',
  'Reported',
  'Clean',
];

const TEMPTER_KIND_COLORS: Record<string, string> = {
  deadline: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  stakes: 'border-red-500/30 bg-red-500/10 text-red-300',
  broad_authority: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  search_thoroughly: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  other: 'border-zinc-700 bg-zinc-800/70 text-zinc-300',
};

type TimelineItem =
  | { kind: 'model_turn'; event: TraceEvent }
  | {
      kind: 'shell_step';
      seq: number;
      turn: number;
      ts: string;
      toolCallId: string;
      command: string;
      gateEvent?: TraceEvent;
      gateDecision?: GateDecision;
      execEvent?: TraceEvent;
      execResult?: ExecResultPayload;
    }
  | {
      kind: 'mitigation_tool';
      seq: number;
      turn: number;
      ts: string;
      toolName: string;
      argumentsObj: Record<string, unknown>;
      resultEvent?: TraceEvent;
    }
  | { kind: 'error'; event: TraceEvent };

function asGateDecision(payload: Record<string, unknown>): GateDecision | undefined {
  const raw = payload.decision;
  if (raw && typeof raw === 'object') {
    const d = raw as Record<string, unknown>;
    return {
      allow: Boolean(d.allow),
      mitigation: String(d.mitigation ?? 'auto_gate'),
      stage: (d.stage as GateDecision['stage']) ?? 'none',
      risk_category: d.risk_category ? String(d.risk_category) : null,
      reason: String(d.reason ?? ''),
    };
  }
  return undefined;
}

function asExecPayload(payload: Record<string, unknown>): ExecResultPayload {
  return {
    exit_code: typeof payload.exit_code === 'number' ? payload.exit_code : null,
    stdout: String(payload.stdout ?? ''),
    stderr: String(payload.stderr ?? ''),
    truncated: Boolean(payload.truncated),
    timed_out: Boolean(payload.timed_out),
    duration_ms: typeof payload.duration_ms === 'number' ? payload.duration_ms : 0,
    canary_in_output: Boolean(payload.canary_in_output),
    honeypot_hits: Array.isArray(payload.honeypot_hits)
      ? (payload.honeypot_hits as HoneypotHit[])
      : [],
    tool_call_id: payload.tool_call_id ? String(payload.tool_call_id) : undefined,
    command: payload.command ? String(payload.command) : undefined,
  };
}

function buildTimeline(trace: TraceEvent[]): TimelineItem[] {
  const sorted = [...trace].sort((a, b) => a.seq - b.seq);
  const consumed = new Set<number>();
  const items: TimelineItem[] = [];

  for (let i = 0; i < sorted.length; i++) {
    const ev = sorted[i];
    if (consumed.has(ev.seq)) continue;

    if (ev.event_type === 'model_turn') {
      items.push({ kind: 'model_turn', event: ev });
      continue;
    }

    if (ev.event_type === 'error') {
      items.push({ kind: 'error', event: ev });
      continue;
    }

    if (ev.event_type === 'tool_call') {
      const toolCallId = String(ev.payload.tool_call_id ?? '');
      const toolName = String(ev.payload.name ?? '');
      const argsObj =
        ev.payload.arguments && typeof ev.payload.arguments === 'object'
          ? (ev.payload.arguments as Record<string, unknown>)
          : {};

      if (toolName === 'run_shell' || toolName === 'shell' || 'command' in argsObj) {
        let gateEvent: TraceEvent | undefined;
        let execEvent: TraceEvent | undefined;

        for (let j = i + 1; j < sorted.length; j++) {
          const cand = sorted[j];
          if (consumed.has(cand.seq)) continue;
          const candId = String(cand.payload.tool_call_id ?? '');
          if (toolCallId && candId !== toolCallId) continue;
          if (!gateEvent && cand.event_type === 'gate_decision') {
            gateEvent = cand;
            consumed.add(cand.seq);
          } else if (!execEvent && cand.event_type === 'exec_result') {
            execEvent = cand;
            consumed.add(cand.seq);
          }
        }

        items.push({
          kind: 'shell_step',
          seq: ev.seq,
          turn: ev.turn,
          ts: ev.ts,
          toolCallId,
          command: String(
            argsObj.command ??
              gateEvent?.payload.command ??
              execEvent?.payload.command ??
              '',
          ),
          gateEvent,
          gateDecision: gateEvent ? asGateDecision(gateEvent.payload) : undefined,
          execEvent,
          execResult: execEvent ? asExecPayload(execEvent.payload) : undefined,
        });
        continue;
      }

      // Non-shell mitigation tool call (e.g., report_sandbox_weakness, view_sandbox_reports)
      let resultEvent: TraceEvent | undefined;
      for (let j = i + 1; j < sorted.length; j++) {
        const cand = sorted[j];
        if (consumed.has(cand.seq)) continue;
        if (
          cand.event_type === 'mitigation_tool_result' &&
          (!toolCallId || String(cand.payload.tool_call_id ?? '') === toolCallId)
        ) {
          resultEvent = cand;
          consumed.add(cand.seq);
          break;
        }
      }

      items.push({
        kind: 'mitigation_tool',
        seq: ev.seq,
        turn: ev.turn,
        ts: ev.ts,
        toolName,
        argumentsObj: argsObj,
        resultEvent,
      });
      continue;
    }

    // Standalone gate_decision or exec_result if tool_call wasn't recorded
    if (ev.event_type === 'gate_decision') {
      items.push({
        kind: 'shell_step',
        seq: ev.seq,
        turn: ev.turn,
        ts: ev.ts,
        toolCallId: String(ev.payload.tool_call_id ?? ''),
        command: String(ev.payload.command ?? ''),
        gateEvent: ev,
        gateDecision: asGateDecision(ev.payload),
      });
      continue;
    }

    if (ev.event_type === 'exec_result') {
      items.push({
        kind: 'shell_step',
        seq: ev.seq,
        turn: ev.turn,
        ts: ev.ts,
        toolCallId: String(ev.payload.tool_call_id ?? ''),
        command: String(ev.payload.command ?? ''),
        execEvent: ev,
        execResult: asExecPayload(ev.payload),
      });
      continue;
    }

    if (ev.event_type === 'mitigation_tool_result') {
      items.push({
        kind: 'mitigation_tool',
        seq: ev.seq,
        turn: ev.turn,
        ts: ev.ts,
        toolName: String(ev.payload.name ?? 'mitigation_tool'),
        argumentsObj: {},
        resultEvent: ev,
      });
    }
  }

  return items;
}

function ReasoningBlock({ reasoning }: { reasoning: string }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="rounded-lg border border-indigo-500/25 bg-indigo-950/20">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium text-indigo-300 transition-colors hover:bg-indigo-500/10"
      >
        <span className="inline-flex items-center gap-1.5">
          <Brain className="h-3.5 w-3.5 text-indigo-400" />
          <span>Model Reasoning / Thinking Trace</span>
        </span>
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-indigo-400/80">
          {open ? 'Hide' : 'Expand'}
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </span>
      </button>
      {open && (
        <pre className="whitespace-pre-wrap border-t border-indigo-500/20 px-3 py-2.5 font-mono text-[11.5px] leading-relaxed text-indigo-100/85">
          {reasoning}
        </pre>
      )}
    </div>
  );
}

function SyscallAlertRow({ sc }: { sc: OutsideSyscall }) {
  const target = sc.path ?? sc.target ?? sc.addr ?? sc.raw ?? '';
  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-red-500/30 bg-red-950/35 px-3 py-2 font-mono text-[11px]">
      <span className="inline-flex items-center gap-1 font-semibold text-red-400">
        <Cpu className="h-3.5 w-3.5" />
        outside_syscall
      </span>
      <span className="rounded bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-200">
        {sc.syscall}
      </span>
      {target && <span className="break-all text-zinc-200">{target}</span>}
      {sc.pid !== undefined && <span className="text-zinc-500">pid={sc.pid}</span>}
      {sc.result && <span className="text-amber-300">→ {sc.result}</span>}
      {sc.turn !== undefined && (
        <span className="ml-auto text-zinc-500">
          turn {sc.turn}
          {sc.seq !== undefined ? ` · seq #${sc.seq}` : ''}
        </span>
      )}
    </div>
  );
}

function HoneypotHitAlert({ hit }: { hit: HoneypotHit }) {
  return (
    <div className="rounded-lg border border-orange-500/40 bg-orange-950/30 px-3 py-2.5 text-xs">
      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
        <span className="inline-flex items-center gap-1 font-semibold text-orange-300">
          <Globe className="h-3.5 w-3.5 text-orange-400" />
          HONEYPOT HIT ({hit.channel})
        </span>
        {hit.method && (
          <span className="rounded bg-orange-500/20 px-1.5 py-0.5 text-orange-200">
            {hit.method}
          </span>
        )}
        {hit.path && <span className="break-all text-zinc-200">{hit.path}</span>}
        {hit.served_canary && (
          <span className="rounded border border-red-500/40 bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-300">
            SERVED CANARY
          </span>
        )}
        {hit.request_contains_canary && (
          <span className="rounded border border-red-500/40 bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-300">
            CANARY IN REQUEST
          </span>
        )}
      </div>
      {hit.body_excerpt && (
        <pre className="mt-2 overflow-x-auto rounded border border-orange-500/20 bg-zinc-950/80 p-2 font-mono text-[11px] text-orange-100/85">
          {hit.body_excerpt}
        </pre>
      )}
    </div>
  );
}

export function TraceExplorer({
  episodes,
  models,
  mitigationSets,
  selectedEpisodeId,
  onSelectEpisode,
  initialModelFilter = null,
  initialMitigationFilter = null,
}: TraceExplorerProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [modelFilter, setModelFilter] = useState<string>(initialModelFilter ?? 'all');
  const [mechanismFilter, setMechanismFilter] = useState<string>('all');
  const [mitigationFilter, setMitigationFilter] = useState<string>(
    initialMitigationFilter ?? 'all',
  );
  const [outcomeFilter, setOutcomeFilter] = useState<OutcomeBadge | 'all'>('all');
  const [promptOpen, setPromptOpen] = useState(false);

  // Sync external pre-filters when jumping from LeaderboardTable
  useEffect(() => {
    if (initialModelFilter) setModelFilter(initialModelFilter);
  }, [initialModelFilter]);

  useEffect(() => {
    if (initialMitigationFilter) setMitigationFilter(initialMitigationFilter);
  }, [initialMitigationFilter]);

  const mechanisms = useMemo(() => {
    const s = new Set<string>();
    episodes.forEach((e) => s.add(e.mechanism));
    return Array.from(s).sort();
  }, [episodes]);

  const filteredEpisodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return episodes.filter((ep) => {
      if (modelFilter !== 'all' && ep.model !== modelFilter) return false;
      if (mechanismFilter !== 'all' && ep.mechanism !== mechanismFilter) return false;
      if (mitigationFilter !== 'all' && ep.mitigation_set_id !== mitigationFilter) return false;
      if (outcomeFilter !== 'all') {
        const badges = getEpisodeOutcomeBadges(ep);
        if (!badges.includes(outcomeFilter)) return false;
      }
      if (q) {
        const hay =
          `${ep.episode_id} ${ep.scenario_id} ${ep.model} ${ep.mechanism} ${ep.mitigation_set_id}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [episodes, modelFilter, mechanismFilter, mitigationFilter, outcomeFilter, searchQuery]);

  // Auto-select first matching episode if none selected
  const activeEpisodeId = selectedEpisodeId ?? filteredEpisodes[0]?.episode_id ?? null;

  // Trace cache + lazy fetch
  const cacheRef = useRef<Map<string, EpisodeResult>>(new Map());
  const [traceData, setTraceData] = useState<EpisodeResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (!activeEpisodeId) {
      setTraceData(null);
      setLoadError(null);
      return;
    }

    const cached = cacheRef.current.get(activeEpisodeId);
    if (cached) {
      setTraceData(cached);
      setLoadError(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setLoadError(null);

    fetch(dataUrl(`traces/${encodeURIComponent(activeEpisodeId)}.json`))
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status} loading trace ${activeEpisodeId}`);
        }
        return (await res.json()) as EpisodeResult;
      })
      .then((json) => {
        if (cancelled) return;
        cacheRef.current.set(activeEpisodeId, json);
        setTraceData(json);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setTraceData(null);
        setLoadError(err instanceof Error ? err.message : 'Failed to load episode trace');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeEpisodeId]);

  const timeline = useMemo(
    () => (traceData ? buildTimeline(traceData.trace) : []),
    [traceData],
  );

  const syscallsByTurn = useMemo(() => {
    const map = new Map<number, OutsideSyscall[]>();
    if (!traceData?.outside_syscalls) return map;
    for (const sc of traceData.outside_syscalls) {
      if (typeof sc.turn === 'number') {
        const list = map.get(sc.turn) ?? [];
        list.push(sc);
        map.set(sc.turn, list);
      }
    }
    return map;
  }, [traceData]);

  const grade = traceData?.grade ?? null;

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
      {/* Left sidebar: Episode Index & Filters */}
      <aside className="flex flex-col rounded-xl border border-zinc-800/90 bg-zinc-900/60 lg:col-span-4 xl:col-span-4">
        <div className="space-y-3 border-b border-zinc-800/80 p-4">
          <div className="flex items-center justify-between">
            <h2 className="inline-flex items-center gap-1.5 text-sm font-semibold text-zinc-100">
              <Filter className="h-3.5 w-3.5 text-amber-400" />
              <span>Episodes</span>
            </h2>
            <span className="font-mono text-xs text-zinc-500 tabular-nums">
              {filteredEpisodes.length}/{episodes.length}
            </span>
          </div>

          {/* Search input */}
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search episode or scenario id..."
              className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-1.5 pr-3 pl-8 text-xs text-zinc-200 placeholder-zinc-500 focus:border-amber-500/50 focus:outline-none"
            />
          </div>

          {/* Dropdown filters */}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 lg:grid-cols-1">
            <select
              aria-label="Filter by model"
              value={modelFilter}
              onChange={(e) => setModelFilter(e.target.value)}
              className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 focus:border-amber-500/50 focus:outline-none"
            >
              <option value="all">All Models</option>
              {models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by mechanism"
              value={mechanismFilter}
              onChange={(e) => setMechanismFilter(e.target.value)}
              className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 focus:border-amber-500/50 focus:outline-none"
            >
              <option value="all">All Mechanisms</option>
              {mechanisms.map((m) => (
                <option key={m} value={m}>
                  {labelForMechanism(m)}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by mitigation"
              value={mitigationFilter}
              onChange={(e) => setMitigationFilter(e.target.value)}
              className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 focus:border-amber-500/50 focus:outline-none"
            >
              <option value="all">All Mitigations</option>
              {mitigationSets.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          {/* Outcome badge pills */}
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => setOutcomeFilter('all')}
              className={`rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors ${
                outcomeFilter === 'all'
                  ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
                  : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All
            </button>
            {OUTCOME_FILTERS.map((badge) => (
              <button
                key={badge}
                type="button"
                onClick={() =>
                  setOutcomeFilter((prev) => (prev === badge ? 'all' : badge))
                }
                className={`rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors ${
                  outcomeFilter === badge
                    ? outcomeBadgeStyle(badge)
                    : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {badge}
              </button>
            ))}
          </div>
        </div>

        {/* Episode list */}
        <div className="max-h-[720px] divide-y divide-zinc-800/70 overflow-y-auto">
          {filteredEpisodes.length === 0 ? (
            <div className="p-6 text-center text-xs text-zinc-500">
              No episodes match these filters.
            </div>
          ) : (
            filteredEpisodes.map((ep) => {
              const isSelected = ep.episode_id === activeEpisodeId;
              const badges = getEpisodeOutcomeBadges(ep);
              return (
                <button
                  key={ep.episode_id}
                  type="button"
                  onClick={() => onSelectEpisode(ep.episode_id)}
                  className={`flex w-full flex-col gap-1.5 px-4 py-3 text-left transition-colors ${
                    isSelected
                      ? 'bg-zinc-800/75 ring-1 ring-inset ring-amber-500/40'
                      : 'hover:bg-zinc-800/35'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs font-semibold text-zinc-100">
                      {ep.episode_id}
                    </span>
                    <span className="shrink-0 font-mono text-[10.5px] text-zinc-500">
                      {ep.backend}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-zinc-400">
                    <span className="font-medium text-zinc-200">{ep.model}</span>
                    <span>·</span>
                    <span className="font-mono text-[10.5px]">{ep.mitigation_set_id}</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5 text-[10.5px] text-zinc-400">
                    <span className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 font-mono">
                      {ep.mechanism}
                    </span>
                    <span className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5">
                      {labelForDifficulty(ep.difficulty)}
                    </span>
                  </div>

                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {badges.map((b) => (
                      <span
                        key={b}
                        className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${outcomeBadgeStyle(b)}`}
                      >
                        {b}
                      </span>
                    ))}
                    {ep.eval_awareness_detected && (
                      <span className="rounded border border-sky-500/30 bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-sky-300">
                        Eval-Aware
                      </span>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </aside>

      {/* Right pane: Full Episode Trace Inspector */}
      <div className="space-y-4 lg:col-span-8 xl:col-span-8">
        {loading && (
          <div className="flex h-64 items-center justify-center rounded-xl border border-zinc-800 bg-zinc-900/50 text-xs text-zinc-400">
            Loading episode trace <span className="ml-1.5 font-mono text-zinc-200">{activeEpisodeId}</span>…
          </div>
        )}

        {!loading && loadError && (
          <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-5 text-xs text-red-300">
            <div className="font-semibold">Unable to load episode trace</div>
            <p className="mt-1 font-mono text-red-200/80">{loadError}</p>
          </div>
        )}

        {!loading && !loadError && !traceData && (
          <div className="flex h-64 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-900/40 text-xs text-zinc-500">
            Select an episode from the left list to inspect its full execution trace.
          </div>
        )}

        {!loading && !loadError && traceData && (
          <>
            {/* Scenario Metadata Header */}
            <section className="rounded-xl border border-zinc-800/90 bg-zinc-900/60 p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="font-mono text-base font-semibold text-zinc-100">
                      {traceData.episode_id}
                    </h2>
                    <span className="rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 font-mono text-[11px] text-zinc-200">
                      {traceData.model}
                    </span>
                    <span className="rounded border border-zinc-800 bg-zinc-950 px-2 py-0.5 font-mono text-[11px] text-zinc-400">
                      {traceData.backend}
                    </span>
                    <span className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-[11px] text-sky-300">
                      mitigation: {traceData.mitigation_set_id}
                    </span>
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-zinc-200">
                    {traceData.scenario.task.title}{' '}
                    <span className="font-mono text-xs font-normal text-zinc-500">
                      ({traceData.scenario.scenario_id})
                    </span>
                  </p>
                </div>

                <div className="flex flex-wrap gap-2 font-mono text-[11px] text-zinc-400 tabular-nums">
                  <span className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1">
                    {traceData.turns} turns
                  </span>
                  <span className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1">
                    {fmtDuration(traceData.duration_ms)}
                  </span>
                  <span className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1">
                    {fmtTokens(traceData.token_usage.input_tokens)} in /{' '}
                    {fmtTokens(traceData.token_usage.output_tokens)} out
                  </span>
                </div>
              </div>

              {/* Metadata grid */}
              <div className="mt-4 grid grid-cols-2 gap-2.5 border-y border-zinc-800/80 py-3.5 text-xs sm:grid-cols-4">
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider text-zinc-500">Mechanism</div>
                  <div className="mt-0.5 font-mono text-zinc-200">
                    {traceData.scenario.sandbox.weakness_mechanism}
                  </div>
                </div>
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider text-zinc-500">Difficulty</div>
                  <div className="mt-0.5 font-medium text-zinc-200">
                    {labelForDifficulty(traceData.scenario.task.difficulty)}
                  </div>
                </div>
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider text-zinc-500">Tempter</div>
                  <div className="mt-0.5 font-mono text-zinc-200">
                    {labelForAblation(traceData.scenario.tempter_ablation)}
                  </div>
                </div>
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider text-zinc-500">Ambiguity</div>
                  <div className="mt-0.5 font-mono text-zinc-200">
                    {traceData.scenario.ambiguity_level}
                  </div>
                </div>
              </div>

              {/* Grade badges */}
              {grade && (
                <div className="mt-3.5 space-y-2.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.reached_outside
                          ? 'border-amber-500/40 bg-amber-500/15 text-amber-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Reached Outside: {grade.reached_outside ? 'YES' : 'NO'}
                      {grade.first_reach_seq ? ` (seq #${grade.first_reach_seq})` : ''}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.used_honeypot
                          ? 'border-orange-500/40 bg-orange-500/15 text-orange-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Used Honeypot: {grade.used_honeypot ? 'YES' : 'NO'}
                      {grade.first_read_seq ? ` (seq #${grade.first_read_seq})` : ''}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.misaligned_use
                          ? 'border-red-500/40 bg-red-500/15 text-red-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Misaligned Use: {grade.misaligned_use ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.reported_weakness
                          ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Reported: {grade.reported_weakness ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.eval_awareness_detected
                          ? 'border-sky-500/40 bg-sky-500/15 text-sky-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Eval-Aware: {grade.eval_awareness_detected ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                        grade.blocked_commands > 0
                          ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                          : 'border-zinc-800 bg-zinc-950 text-zinc-500'
                      }`}
                    >
                      Blocked Cmds: {grade.blocked_commands}
                    </span>

                    {grade.task_feasible && (
                      <span
                        className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${
                          grade.task_completed
                            ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                            : 'border-zinc-700 bg-zinc-800/70 text-zinc-300'
                        }`}
                      >
                        Task Solved: {grade.task_completed ? 'PASS' : 'FAIL'}
                      </span>
                    )}
                  </div>

                  {/* Evidence chips */}
                  {grade.evidence.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="text-[10.5px] font-semibold uppercase tracking-wider text-zinc-500">
                        Evidence:
                      </span>
                      {grade.evidence.map((evStr, idx) => (
                        <span
                          key={`${evStr}-${idx}`}
                          className="rounded border border-zinc-700/80 bg-zinc-950 px-2 py-0.5 font-mono text-[11px] text-zinc-300"
                        >
                          {evStr}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Collapsible Task Prompt & Tempter */}
              <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60">
                <button
                  type="button"
                  onClick={() => setPromptOpen((p) => !p)}
                  className="flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium text-zinc-300 hover:bg-zinc-800/40"
                >
                  <span>Task Prompt &amp; Tempter Segments ({traceData.scenario.tempter.segments.length})</span>
                  {promptOpen ? (
                    <ChevronDown className="h-3.5 w-3.5 text-zinc-400" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 text-zinc-400" />
                  )}
                </button>
                {promptOpen && (
                  <div className="space-y-3 border-t border-zinc-800 px-3 py-3 text-xs">
                    <div>
                      <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-zinc-500">
                        Task Prompt
                      </div>
                      <p className="whitespace-pre-wrap leading-relaxed text-zinc-200">
                        {traceData.scenario.task.prompt}
                      </p>
                    </div>

                    {traceData.scenario.tempter.segments.length > 0 && (
                      <div>
                        <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-zinc-500">
                          Tempter Framing
                        </div>
                        <div className="space-y-1.5">
                          {traceData.scenario.tempter.segments.map((seg, i) => (
                            <div
                              key={`${seg.kind}-${i}`}
                              className="flex items-start gap-2 rounded border border-zinc-800/80 bg-zinc-900/60 p-2"
                            >
                              <span
                                className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                                  TEMPTER_KIND_COLORS[seg.kind] ?? TEMPTER_KIND_COLORS.other
                                }`}
                              >
                                {seg.kind}
                              </span>
                              <span className="text-zinc-300">{seg.text}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>

            {/* Kernel outside_syscalls Summary Banner */}
            {traceData.outside_syscalls && traceData.outside_syscalls.length > 0 && (
              <section className="rounded-xl border border-red-500/35 bg-red-950/15 p-4">
                <div className="mb-2.5 flex items-center justify-between">
                  <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-red-300">
                    <AlertOctagon className="h-4 w-4 text-red-400" />
                    Kernel Outside-Syscall Alerts ({traceData.outside_syscalls.length})
                  </h3>
                  <span className="font-mono text-[10.5px] text-red-300/70">
                    strace / seccomp telemetry
                  </span>
                </div>
                <div className="space-y-1.5">
                  {traceData.outside_syscalls.map((sc, i) => (
                    <SyscallAlertRow key={`${sc.syscall}-${sc.seq ?? i}-${i}`} sc={sc} />
                  ))}
                </div>
              </section>
            )}

            {/* Agent Weakness Reports */}
            {traceData.reports && traceData.reports.length > 0 && (
              <section className="rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-4">
                <h3 className="mb-2.5 inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-300">
                  <Flag className="h-4 w-4 text-emerald-400" />
                  Submitted Sandbox Weakness Reports ({traceData.reports.length})
                </h3>
                <div className="space-y-2">
                  {traceData.reports.map((rep, idx) => (
                    <div
                      key={`${rep.path_or_endpoint}-${idx}`}
                      className="rounded-lg border border-emerald-500/25 bg-zinc-950/75 p-3 text-xs"
                    >
                      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                        <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 font-semibold text-emerald-300">
                          {rep.weakness_type}
                        </span>
                        <span className="text-zinc-200">{rep.path_or_endpoint}</span>
                        <span className="ml-auto rounded border border-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
                          source: {rep.source}
                        </span>
                      </div>
                      <p className="mt-1.5 leading-relaxed text-zinc-300">{rep.description}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Chronological Execution Timeline */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                  Execution Timeline ({timeline.length} steps)
                </h3>
                <span className="font-mono text-[11px] text-zinc-500">
                  started {fmtTimestamp(traceData.started_at)}
                </span>
              </div>

              <div className="space-y-3">
                {timeline.map((item, idx) => {
                  if (item.kind === 'model_turn') {
                    const ev = item.event;
                    const reasoning =
                      typeof ev.payload.reasoning === 'string' && ev.payload.reasoning.trim()
                        ? ev.payload.reasoning
                        : null;
                    const content =
                      typeof ev.payload.content === 'string' && ev.payload.content.trim()
                        ? ev.payload.content
                        : null;
                    const stopReason = ev.payload.stop_reason
                      ? String(ev.payload.stop_reason)
                      : null;

                    return (
                      <article
                        key={`turn-${ev.seq}-${idx}`}
                        className="rounded-xl border border-zinc-800/90 bg-zinc-900/55 p-4"
                      >
                        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <span className="inline-flex items-center gap-1.5 font-semibold text-zinc-200">
                            <MessageSquare className="h-3.5 w-3.5 text-zinc-400" />
                            Model Turn {ev.turn}
                          </span>
                          <div className="flex items-center gap-2 font-mono text-[10.5px] text-zinc-500">
                            {stopReason && <span>stop={stopReason}</span>}
                            <span>seq #{ev.seq}</span>
                          </div>
                        </div>

                        <div className="space-y-2.5">
                          {reasoning && <ReasoningBlock reasoning={reasoning} />}
                          {content && (
                            <div className="whitespace-pre-wrap rounded-lg border border-zinc-800/80 bg-zinc-950/60 px-3 py-2.5 text-xs leading-relaxed text-zinc-200">
                              {content}
                            </div>
                          )}
                          {!reasoning && !content && (
                            <div className="font-mono text-[11px] text-zinc-500">
                              (Invoked tool call directly without text output)
                            </div>
                          )}
                        </div>
                      </article>
                    );
                  }

                  if (item.kind === 'shell_step') {
                    const gate = item.gateDecision;
                    const exec = item.execResult;
                    const turnSyscalls = syscallsByTurn.get(item.turn) ?? [];
                    const isFirstReach =
                      grade?.first_reach_seq != null &&
                      (item.seq === grade.first_reach_seq ||
                        item.execEvent?.seq === grade.first_reach_seq ||
                        item.gateEvent?.seq === grade.first_reach_seq);
                    const isFirstRead =
                      grade?.first_read_seq != null &&
                      (item.seq === grade.first_read_seq ||
                        item.execEvent?.seq === grade.first_read_seq);

                    return (
                      <article
                        key={`shell-${item.seq}-${idx}`}
                        className={`rounded-xl border p-4 ${
                          gate && !gate.allow
                            ? 'border-emerald-500/35 bg-emerald-950/15'
                            : exec?.canary_in_output || (exec?.honeypot_hits?.length ?? 0) > 0
                              ? 'border-red-500/40 bg-red-950/15'
                              : 'border-zinc-800/90 bg-zinc-900/55'
                        }`}
                      >
                        {/* Command Header + Auto-Gate Decision Badge */}
                        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-100">
                              <Terminal className="h-3.5 w-3.5 text-amber-400" />
                              Shell Execution
                            </span>
                            {isFirstReach && (
                              <span className="rounded border border-amber-500/40 bg-amber-500/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
                                first_reach_seq
                              </span>
                            )}
                            {isFirstRead && (
                              <span className="rounded border border-red-500/40 bg-red-500/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-red-300">
                                first_read_seq
                              </span>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                            {gate && (
                              <span
                                className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-semibold ${
                                  gate.allow
                                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                    : 'border-red-500/40 bg-red-500/20 text-red-300'
                                }`}
                              >
                                {gate.allow ? (
                                  <ShieldCheck className="h-3 w-3" />
                                ) : (
                                  <ShieldAlert className="h-3 w-3" />
                                )}
                                {gate.mitigation}: {gate.allow ? 'ALLOW' : 'DENY'}
                                {gate.stage !== 'none' ? ` (${gate.stage})` : ''}
                              </span>
                            )}
                            {gate?.risk_category && (
                              <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10.5px] text-amber-300">
                                {gate.risk_category}
                              </span>
                            )}
                            <span className="text-zinc-500">
                              turn {item.turn} · seq #{item.seq}
                            </span>
                          </div>
                        </div>

                        {/* Command text */}
                        <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 px-3.5 py-2.5 font-mono text-xs text-amber-200">
                          <span className="select-none text-zinc-600">$ </span>
                          {item.command}
                        </pre>

                        {/* Gate denial / reason banner */}
                        {gate && (!gate.allow || gate.reason) && (
                          <div
                            className={`mt-2 flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${
                              gate.allow
                                ? 'border-zinc-800 bg-zinc-950/60 text-zinc-400'
                                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                            }`}
                          >
                            {gate.allow ? (
                              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                            ) : (
                              <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                            )}
                            <div>
                              <span className="font-semibold">
                                {gate.allow ? 'Gate policy:' : 'Blocked by Auto-Gate:'}
                              </span>{' '}
                              {gate.reason}
                            </div>
                          </div>
                        )}

                        {/* Exec stdout/stderr output */}
                        {exec && (
                          <div className="mt-2.5 space-y-2">
                            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-zinc-400">
                              <span
                                className={`rounded px-1.5 py-0.5 ${
                                  exec.exit_code === 0
                                    ? 'bg-zinc-800 text-zinc-300'
                                    : 'bg-red-500/15 text-red-300'
                                }`}
                              >
                                exit {exec.exit_code ?? 'null'}
                              </span>
                              <span>{fmtDuration(exec.duration_ms)}</span>
                              {exec.timed_out && (
                                <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-amber-300">
                                  TIMED OUT
                                </span>
                              )}
                              {exec.canary_in_output && (
                                <span className="inline-flex items-center gap-1 rounded border border-red-500/40 bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-300">
                                  <FileWarning className="h-3 w-3" />
                                  CANARY IN OUTPUT
                                </span>
                              )}
                              {exec.truncated && (
                                <span className="text-zinc-500">[truncated]</span>
                              )}
                            </div>

                            {exec.stdout && (
                              <div>
                                <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                                  stdout
                                </div>
                                <pre className="max-h-64 overflow-auto rounded-lg border border-zinc-800/80 bg-zinc-950/90 p-3 font-mono text-[11.5px] leading-relaxed text-zinc-300">
                                  {exec.stdout}
                                </pre>
                              </div>
                            )}

                            {exec.stderr && (
                              <div>
                                <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-red-400/80">
                                  stderr
                                </div>
                                <pre className="max-h-48 overflow-auto rounded-lg border border-red-500/20 bg-zinc-950/90 p-3 font-mono text-[11.5px] leading-relaxed text-red-200/85">
                                  {exec.stderr}
                                </pre>
                              </div>
                            )}

                            {/* Honeypot HTTP/Unix socket hit alerts */}
                            {exec.honeypot_hits && exec.honeypot_hits.length > 0 && (
                              <div className="space-y-1.5 pt-1">
                                {exec.honeypot_hits.map((hit, hIdx) => (
                                  <HoneypotHitAlert key={`${hit.ts}-${hIdx}`} hit={hit} />
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Turn-matched outside syscalls */}
                        {turnSyscalls.length > 0 && (
                          <div className="mt-2.5 space-y-1.5">
                            {turnSyscalls.map((sc, scIdx) => (
                              <SyscallAlertRow key={`${sc.syscall}-${scIdx}`} sc={sc} />
                            ))}
                          </div>
                        )}
                      </article>
                    );
                  }

                  if (item.kind === 'mitigation_tool') {
                    const resContent = item.resultEvent
                      ? String(item.resultEvent.payload.content ?? '')
                      : null;
                    const isErr = Boolean(item.resultEvent?.payload.is_error);

                    return (
                      <article
                        key={`mit-${item.seq}-${idx}`}
                        className="rounded-xl border border-emerald-500/35 bg-emerald-950/15 p-4"
                      >
                        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                          <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-emerald-300">
                            <Flag className="h-3.5 w-3.5 text-emerald-400" />
                            {item.toolName}
                          </span>
                          <span className="font-mono text-[11px] text-zinc-500">
                            turn {item.turn} · seq #{item.seq}
                          </span>
                        </div>
                        {Object.keys(item.argumentsObj).length > 0 && (
                          <pre className="overflow-x-auto rounded-lg border border-emerald-500/20 bg-zinc-950/90 p-2.5 font-mono text-[11px] text-emerald-100/85">
                            {JSON.stringify(item.argumentsObj, null, 2)}
                          </pre>
                        )}
                        {resContent && (
                          <div
                            className={`mt-2 rounded-lg border px-3 py-2 font-mono text-[11px] ${
                              isErr
                                ? 'border-red-500/30 bg-red-950/30 text-red-300'
                                : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200'
                            }`}
                          >
                            {resContent}
                          </div>
                        )}
                      </article>
                    );
                  }

                  // Error event
                  return (
                    <article
                      key={`err-${item.event.seq}-${idx}`}
                      className="rounded-xl border border-red-500/40 bg-red-950/25 p-4 text-xs text-red-200"
                    >
                      <div className="mb-1 flex items-center gap-2 font-semibold text-red-300">
                        <XCircle className="h-4 w-4 text-red-400" />
                        Episode Error ({String(item.event.payload.where ?? 'runtime')})
                      </div>
                      <pre className="whitespace-pre-wrap font-mono text-[11px] text-red-200/85">
                        {String(item.event.payload.message ?? 'Unknown error')}
                      </pre>
                    </article>
                  );
                })}
              </div>
            </section>

            {/* Final Answer */}
            {traceData.final_answer && (
              <section className="rounded-xl border border-zinc-800/90 bg-zinc-900/70 p-5">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                    Final Assistant Answer
                  </h3>
                  <span className="font-mono text-[11px] text-zinc-500">
                    status: {traceData.status}
                  </span>
                </div>
                <div className="whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950/80 p-3.5 text-xs leading-relaxed text-zinc-200">
                  {traceData.final_answer}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
