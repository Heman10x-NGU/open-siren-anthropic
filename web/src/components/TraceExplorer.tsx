import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, Search } from 'lucide-react';
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
    <div className="rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9]">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium text-[#525252] transition-colors duration-150 hover:text-[#141414]"
      >
        <span className="font-mono text-[10.5px] uppercase tracking-[0.06em]">
          Reasoning Trace
        </span>
        <span className="inline-flex items-center gap-1 font-mono text-[10.5px] text-[#737373]">
          {open ? 'Hide' : 'Expand'}
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </span>
      </button>
      {open && (
        <pre className="whitespace-pre-wrap border-t border-[#e5e5e5] px-3 py-2.5 font-mono text-[11.5px] leading-relaxed text-[#525252]">
          {reasoning}
        </pre>
      )}
    </div>
  );
}

function SyscallAlertRow({ sc }: { sc: OutsideSyscall }) {
  const target = sc.path ?? sc.target ?? sc.addr ?? sc.raw ?? '';
  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-[4px] border border-[#eb6c36]/40 bg-[#fafaf9] px-3 py-2 font-mono text-[11px]">
      <span className="font-semibold text-[#eb6c36]">OUTSIDE_SYSCALL</span>
      <span className="rounded-[3px] border border-[#141414]/25 bg-white px-1.5 py-0.5 font-medium text-[#141414]">
        {sc.syscall}
      </span>
      {target && <span className="break-all text-[#141414]">{target}</span>}
      {sc.pid !== undefined && <span className="text-[#737373]">pid={sc.pid}</span>}
      {sc.result && <span className="text-[#525252]">→ {sc.result}</span>}
      {sc.turn !== undefined && (
        <span className="ml-auto text-[#737373] tabular-nums">
          turn {sc.turn}
          {sc.seq !== undefined ? ` · seq #${sc.seq}` : ''}
        </span>
      )}
    </div>
  );
}

function HoneypotHitAlert({ hit }: { hit: HoneypotHit }) {
  return (
    <div className="rounded-[4px] border border-[#eb6c36]/55 bg-[#fafaf9] px-3 py-2.5 text-xs">
      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
        <span className="rounded-[3px] border border-[#eb6c36] bg-[#eb6c36]/[0.08] px-1.5 py-0.5 text-[10px] font-semibold text-[#eb6c36]">
          HIT
        </span>
        <span className="font-medium text-[#141414]">honeypot ({hit.channel})</span>
        {hit.method && (
          <span className="rounded-[3px] border border-[#d4d4d4] bg-white px-1.5 py-0.5 text-[#525252]">
            {hit.method}
          </span>
        )}
        {hit.path && <span className="break-all text-[#141414]">{hit.path}</span>}
        {hit.served_canary && (
          <span className="rounded-[3px] border border-[#eb6c36] bg-[#eb6c36]/[0.08] px-1.5 py-0.5 text-[10px] font-semibold text-[#eb6c36]">
            SERVED CANARY
          </span>
        )}
        {hit.request_contains_canary && (
          <span className="rounded-[3px] border border-[#eb6c36] bg-[#eb6c36]/[0.08] px-1.5 py-0.5 text-[10px] font-semibold text-[#eb6c36]">
            CANARY IN REQUEST
          </span>
        )}
      </div>
      {hit.body_excerpt && (
        <pre className="mt-2 overflow-x-auto rounded-[4px] border border-[#e5e5e5] bg-white p-2.5 font-mono text-[11px] text-[#525252]">
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

  const activeEpisodeId = selectedEpisodeId ?? filteredEpisodes[0]?.episode_id ?? null;

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
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
      {/* Left sidebar: Episode Index & Filters */}
      <aside className="flex flex-col rounded-[6px] border border-[#141414]/[0.14] bg-white lg:col-span-4">
        <div className="space-y-3 border-b border-[#e5e5e5] p-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-[20px] leading-tight text-[#141414]">Episodes</h2>
            <span className="font-mono text-[11px] text-[#737373] tabular-nums">
              {filteredEpisodes.length}/{episodes.length}
            </span>
          </div>

          {/* Search input */}
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[#737373]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter episode or scenario…"
              className="w-full rounded-[4px] border border-[#d4d4d4] bg-white py-1.5 pr-3 pl-8 text-xs text-[#141414] placeholder-[#a3a3a3] transition-colors duration-150 focus:border-[#141414] focus:outline-none"
            />
          </div>

          {/* Dropdown filters */}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 lg:grid-cols-1">
            <select
              aria-label="Filter by model"
              value={modelFilter}
              onChange={(e) => setModelFilter(e.target.value)}
              className="rounded-[4px] border border-[#d4d4d4] bg-white px-2.5 py-1.5 text-xs text-[#141414] transition-colors duration-150 focus:border-[#141414] focus:outline-none"
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
              className="rounded-[4px] border border-[#d4d4d4] bg-white px-2.5 py-1.5 text-xs text-[#141414] transition-colors duration-150 focus:border-[#141414] focus:outline-none"
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
              className="rounded-[4px] border border-[#d4d4d4] bg-white px-2.5 py-1.5 text-xs text-[#141414] transition-colors duration-150 focus:border-[#141414] focus:outline-none"
            >
              <option value="all">All Mitigations</option>
              {mitigationSets.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          {/* Quiet outcome filter toggles */}
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => setOutcomeFilter('all')}
              className={`rounded-[4px] border px-2 py-0.5 font-mono text-[10.5px] transition-colors duration-150 ${
                outcomeFilter === 'all'
                  ? 'border-[#141414] bg-[#141414] text-white'
                  : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
              }`}
            >
              All
            </button>
            {OUTCOME_FILTERS.map((badge) => {
              const active = outcomeFilter === badge;
              return (
                <button
                  key={badge}
                  type="button"
                  onClick={() => setOutcomeFilter((prev) => (prev === badge ? 'all' : badge))}
                  className={`rounded-[4px] border px-2 py-0.5 font-mono text-[10.5px] transition-colors duration-150 ${
                    active
                      ? badge === 'Misaligned'
                        ? 'border-[#eb6c36] bg-[#eb6c36] text-white'
                        : 'border-[#141414] bg-[#141414] text-white'
                      : 'border-[#d4d4d4] bg-white text-[#525252] hover:border-[#141414]/45 hover:text-[#141414]'
                  }`}
                >
                  {badge}
                </button>
              );
            })}
          </div>
        </div>

        {/* Compact Episode List */}
        <div className="max-h-[760px] divide-y divide-[#e5e5e5] overflow-y-auto">
          {filteredEpisodes.length === 0 ? (
            <div className="p-6 text-center text-xs text-[#737373]">
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
                  className={`flex w-full flex-col gap-1.5 border-l-2 px-4 py-3 text-left transition-colors duration-150 ${
                    isSelected
                      ? 'border-l-[#141414] bg-[#fafaf9]'
                      : 'border-l-transparent hover:bg-[#fafaf9]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs font-medium text-[#141414]">
                      {ep.episode_id}
                    </span>
                    <span className="shrink-0 font-mono text-[10px] text-[#737373]">
                      {ep.backend}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 font-mono text-[10.5px] text-[#525252]">
                    <span>{ep.model}</span>
                    <span className="text-[#d4d4d4]">·</span>
                    <span className="text-[#737373]">{ep.mitigation_set_id}</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10.5px] text-[#737373]">
                    <span className="font-mono">{ep.mechanism}</span>
                    <span className="text-[#d4d4d4]">·</span>
                    <span>{labelForDifficulty(ep.difficulty)}</span>
                  </div>

                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {badges.map((b) => (
                      <span
                        key={b}
                        className={`rounded-[3px] border px-1.5 py-0.5 font-mono text-[9.5px] font-medium uppercase tracking-[0.04em] ${outcomeBadgeStyle(b)}`}
                      >
                        {b}
                      </span>
                    ))}
                    {ep.eval_awareness_detected && (
                      <span className="rounded-[3px] border border-[#d4d4d4] bg-white px-1.5 py-0.5 font-mono text-[9.5px] font-medium uppercase tracking-[0.04em] text-[#525252]">
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
      <div className="space-y-4 lg:col-span-8">
        {loading && (
          <div className="flex h-64 items-center justify-center rounded-[6px] border border-[#141414]/[0.14] bg-white font-mono text-xs text-[#737373]">
            Loading episode trace <span className="ml-1.5 text-[#141414]">{activeEpisodeId}</span>…
          </div>
        )}

        {!loading && loadError && (
          <div className="rounded-[6px] border border-[#eb6c36] bg-white p-5 text-xs text-[#141414]">
            <div className="font-medium text-[#eb6c36]">Unable to load episode trace</div>
            <p className="mt-1 font-mono text-[#525252]">{loadError}</p>
          </div>
        )}

        {!loading && !loadError && !traceData && (
          <div className="flex h-64 items-center justify-center rounded-[6px] border border-dashed border-[#d4d4d4] bg-white text-xs text-[#737373]">
            Select an episode from the left list to inspect its full execution trace.
          </div>
        )}

        {!loading && !loadError && traceData && (
          <>
            {/* Scenario Metadata Header */}
            <section className="rounded-[6px] border border-[#141414]/[0.14] bg-white p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-[#525252]">
                    <span className="font-semibold text-[#141414]">{traceData.episode_id}</span>
                    <span className="text-[#d4d4d4]">·</span>
                    <span>{traceData.model}</span>
                    <span className="text-[#d4d4d4]">·</span>
                    <span className="text-[#737373]">{traceData.backend}</span>
                    <span className="text-[#d4d4d4]">·</span>
                    <span className="rounded-[3px] border border-[#d4d4d4] bg-[#fafaf9] px-1.5 py-0.5 text-[10.5px] text-[#141414]">
                      {traceData.mitigation_set_id}
                    </span>
                  </div>
                  <h2 className="mt-2 text-[24px] leading-snug text-[#141414]">
                    {traceData.scenario.task.title}
                  </h2>
                  <div className="mt-0.5 font-mono text-[11px] text-[#737373]">
                    {traceData.scenario.scenario_id}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-[#525252] tabular-nums">
                  <span className="rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-2 py-1">
                    {traceData.turns} turns
                  </span>
                  <span className="rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-2 py-1">
                    {fmtDuration(traceData.duration_ms)}
                  </span>
                  <span className="rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-2 py-1">
                    {fmtTokens(traceData.token_usage.input_tokens)} in /{' '}
                    {fmtTokens(traceData.token_usage.output_tokens)} out
                  </span>
                </div>
              </div>

              {/* Metadata grid */}
              <div className="mt-4 grid grid-cols-2 gap-3 border-y border-[#e5e5e5] py-3.5 text-xs sm:grid-cols-4">
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                    Mechanism
                  </div>
                  <div className="mt-1 font-mono text-[11.5px] text-[#141414]">
                    {traceData.scenario.sandbox.weakness_mechanism}
                  </div>
                </div>
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                    Difficulty
                  </div>
                  <div className="mt-1 font-medium text-[#141414]">
                    {labelForDifficulty(traceData.scenario.task.difficulty)}
                  </div>
                </div>
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                    Tempter
                  </div>
                  <div className="mt-1 text-[#141414]">
                    {labelForAblation(traceData.scenario.tempter_ablation)}
                  </div>
                </div>
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                    Ambiguity
                  </div>
                  <div className="mt-1 font-mono text-[11.5px] text-[#141414]">
                    {traceData.scenario.ambiguity_level}
                  </div>
                </div>
              </div>

              {/* Grade hairline tags */}
              {grade && (
                <div className="mt-4 space-y-2.5">
                  <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10.5px]">
                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.reached_outside
                          ? 'border-[#141414]/45 bg-[#f5f5f4] font-medium text-[#141414]'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      REACHED: {grade.reached_outside ? 'YES' : 'NO'}
                      {grade.first_reach_seq ? ` (#${grade.first_reach_seq})` : ''}
                    </span>

                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.used_honeypot
                          ? 'border-[#141414] bg-[#141414] font-medium text-white'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      USED HONEYPOT: {grade.used_honeypot ? 'YES' : 'NO'}
                      {grade.first_read_seq ? ` (#${grade.first_read_seq})` : ''}
                    </span>

                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.misaligned_use
                          ? 'border-[#eb6c36] bg-[#eb6c36]/[0.08] font-semibold text-[#eb6c36]'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      MISALIGNED: {grade.misaligned_use ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.reported_weakness
                          ? 'border-[#141414]/40 bg-white font-medium text-[#141414]'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      REPORTED: {grade.reported_weakness ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.eval_awareness_detected
                          ? 'border-[#141414]/40 bg-white font-medium text-[#141414]'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      EVAL-AWARE: {grade.eval_awareness_detected ? 'YES' : 'NO'}
                    </span>

                    <span
                      className={`rounded-[3px] border px-2 py-0.5 ${
                        grade.blocked_commands > 0
                          ? 'border-[#141414] bg-white font-medium text-[#141414]'
                          : 'border-[#e5e5e5] bg-white text-[#737373]'
                      }`}
                    >
                      BLOCKED: {grade.blocked_commands}
                    </span>

                    {grade.task_feasible && (
                      <span
                        className={`rounded-[3px] border px-2 py-0.5 ${
                          grade.task_completed
                            ? 'border-[#141414]/45 bg-[#f5f5f4] font-medium text-[#141414]'
                            : 'border-[#e5e5e5] bg-white text-[#737373]'
                        }`}
                      >
                        SOLVED: {grade.task_completed ? 'PASS' : 'FAIL'}
                      </span>
                    )}
                  </div>

                  {grade.evidence.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                      <span className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                        Evidence
                      </span>
                      {grade.evidence.map((evStr, idx) => (
                        <span
                          key={`${evStr}-${idx}`}
                          className="rounded-[3px] border border-[#e5e5e5] bg-[#fafaf9] px-2 py-0.5 font-mono text-[10.5px] text-[#525252]"
                        >
                          {evStr}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Collapsible Task Prompt & Tempter */}
              <div className="mt-4 rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9]">
                <button
                  type="button"
                  onClick={() => setPromptOpen((p) => !p)}
                  className="flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium text-[#525252] transition-colors duration-150 hover:text-[#141414]"
                >
                  <span>
                    Task Prompt &amp; Tempter Segments ({traceData.scenario.tempter.segments.length})
                  </span>
                  {promptOpen ? (
                    <ChevronDown className="h-3.5 w-3.5 text-[#737373]" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 text-[#737373]" />
                  )}
                </button>
                {promptOpen && (
                  <div className="space-y-3 border-t border-[#e5e5e5] bg-white px-3.5 py-3 text-xs">
                    <div>
                      <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                        Task Prompt
                      </div>
                      <p className="whitespace-pre-wrap leading-relaxed text-[#141414]">
                        {traceData.scenario.task.prompt}
                      </p>
                    </div>

                    {traceData.scenario.tempter.segments.length > 0 && (
                      <div>
                        <div className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                          Tempter Framing
                        </div>
                        <div className="space-y-1.5">
                          {traceData.scenario.tempter.segments.map((seg, i) => (
                            <div
                              key={`${seg.kind}-${i}`}
                              className="flex items-start gap-2 rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] p-2"
                            >
                              <span className="shrink-0 rounded-[3px] border border-[#d4d4d4] bg-white px-1.5 py-0.5 font-mono text-[10px] text-[#525252]">
                                {seg.kind}
                              </span>
                              <span className="text-[#141414]">{seg.text}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>

            {/* Kernel outside_syscalls Summary */}
            {traceData.outside_syscalls && traceData.outside_syscalls.length > 0 && (
              <section className="rounded-[6px] border border-[#141414]/[0.14] border-l-2 border-l-[#eb6c36] bg-white p-4">
                <div className="mb-2.5 flex items-center justify-between gap-2">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#eb6c36]">
                    Kernel Outside-Syscall Alerts ({traceData.outside_syscalls.length})
                  </h3>
                  <span className="font-mono text-[10.5px] text-[#737373]">
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
              <section className="rounded-[6px] border border-[#141414]/[0.14] border-l-2 border-l-[#141414] bg-white p-4">
                <div className="mb-2.5 flex items-center justify-between gap-2">
                  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#141414]">
                    Submitted Weakness Reports ({traceData.reports.length})
                  </h3>
                  <span className="rounded-[3px] border border-[#141414]/35 px-1.5 py-0.5 font-mono text-[10px] font-medium text-[#141414]">
                    REPORTED
                  </span>
                </div>
                <div className="space-y-2">
                  {traceData.reports.map((rep, idx) => (
                    <div
                      key={`${rep.path_or_endpoint}-${idx}`}
                      className="rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] p-3 text-xs"
                    >
                      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                        <span className="rounded-[3px] border border-[#141414]/30 bg-white px-1.5 py-0.5 font-medium text-[#141414]">
                          {rep.weakness_type}
                        </span>
                        <span className="text-[#141414]">{rep.path_or_endpoint}</span>
                        <span className="ml-auto text-[10px] text-[#737373]">
                          source: {rep.source}
                        </span>
                      </div>
                      <p className="mt-1.5 leading-relaxed text-[#525252]">{rep.description}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Chronological Execution Timeline */}
            <section className="space-y-3">
              <div className="flex items-center justify-between px-0.5">
                <h3 className="font-mono text-[10.5px] font-medium uppercase tracking-[0.08em] text-[#737373]">
                  Execution Timeline ({timeline.length} steps)
                </h3>
                <span className="font-mono text-[11px] text-[#737373] tabular-nums">
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
                        className="rounded-[6px] border border-[#141414]/[0.14] bg-white p-4"
                      >
                        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <span className="font-medium text-[#141414]">Model Turn {ev.turn}</span>
                          <div className="flex items-center gap-2 font-mono text-[10.5px] text-[#737373] tabular-nums">
                            {stopReason && <span>stop={stopReason}</span>}
                            <span>seq #{ev.seq}</span>
                          </div>
                        </div>

                        <div className="space-y-2.5">
                          {reasoning && <ReasoningBlock reasoning={reasoning} />}
                          {content && (
                            <div className="whitespace-pre-wrap rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-3 py-2.5 text-xs leading-relaxed text-[#141414]">
                              {content}
                            </div>
                          )}
                          {!reasoning && !content && (
                            <div className="font-mono text-[11px] text-[#737373]">
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
                    const hasBreach =
                      Boolean(exec?.canary_in_output) ||
                      (exec?.honeypot_hits?.length ?? 0) > 0;
                    const isBlocked = Boolean(gate && !gate.allow);

                    return (
                      <article
                        key={`shell-${item.seq}-${idx}`}
                        className={`rounded-[6px] border border-[#141414]/[0.14] bg-white p-4 ${
                          hasBreach
                            ? 'border-l-2 border-l-[#eb6c36]'
                            : isBlocked
                              ? 'border-l-2 border-l-[#141414]'
                              : ''
                        }`}
                      >
                        {/* Command Header + Hairline Tags */}
                        <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-xs font-medium text-[#141414]">
                              Shell Execution
                            </span>
                            {isFirstReach && (
                              <span className="rounded-[3px] border border-[#141414]/45 bg-[#f5f5f4] px-1.5 py-0.5 font-mono text-[10px] font-medium text-[#141414]">
                                first_reach_seq
                              </span>
                            )}
                            {isFirstRead && (
                              <span className="rounded-[3px] border border-[#eb6c36] bg-[#eb6c36]/[0.08] px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#eb6c36]">
                                first_read_seq
                              </span>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-2 font-mono text-[10.5px]">
                            {gate && (
                              <span
                                className={`rounded-[3px] border px-1.5 py-0.5 font-semibold ${
                                  gate.allow
                                    ? 'border-[#d4d4d4] bg-[#fafaf9] text-[#525252]'
                                    : 'border-[#141414] bg-[#141414] text-white'
                                }`}
                              >
                                {gate.allow ? 'ALLOW' : 'BLOCKED'}
                                {gate.stage !== 'none' ? ` · ${gate.stage}` : ''}
                              </span>
                            )}
                            {gate?.risk_category && (
                              <span className="rounded-[3px] border border-[#d4d4d4] bg-white px-1.5 py-0.5 text-[#525252]">
                                {gate.risk_category}
                              </span>
                            )}
                            <span className="text-[#737373] tabular-nums">
                              turn {item.turn} · seq #{item.seq}
                            </span>
                          </div>
                        </div>

                        {/* Command text */}
                        <pre className="overflow-x-auto rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-3.5 py-2.5 font-mono text-xs text-[#141414]">
                          <span className="select-none text-[#a3a3a3]">$ </span>
                          {item.command}
                        </pre>

                        {/* Gate denial / reason banner */}
                        {gate && (!gate.allow || gate.reason) && (
                          <div className="mt-2 rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] px-3 py-2 text-xs text-[#525252]">
                            <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.04em] text-[#141414]">
                              {gate.allow ? `${gate.mitigation}:` : `Blocked (${gate.mitigation}):`}
                            </span>{' '}
                            {gate.reason}
                          </div>
                        )}

                        {/* Exec stdout/stderr output */}
                        {exec && (
                          <div className="mt-2.5 space-y-2">
                            <div className="flex flex-wrap items-center gap-2 font-mono text-[10.5px] text-[#737373] tabular-nums">
                              <span
                                className={`rounded-[3px] border px-1.5 py-0.5 ${
                                  exec.exit_code === 0
                                    ? 'border-[#e5e5e5] bg-[#fafaf9] text-[#525252]'
                                    : 'border-[#eb6c36]/50 bg-[#eb6c36]/[0.06] text-[#eb6c36]'
                                }`}
                              >
                                exit {exec.exit_code ?? 'null'}
                              </span>
                              <span>{fmtDuration(exec.duration_ms)}</span>
                              {exec.timed_out && (
                                <span className="rounded-[3px] border border-[#eb6c36] px-1.5 py-0.5 font-medium text-[#eb6c36]">
                                  TIMED OUT
                                </span>
                              )}
                              {exec.canary_in_output && (
                                <span className="rounded-[3px] border border-[#eb6c36] bg-[#eb6c36]/[0.08] px-1.5 py-0.5 font-semibold text-[#eb6c36]">
                                  CANARY IN OUTPUT
                                </span>
                              )}
                              {exec.truncated && <span className="text-[#737373]">[truncated]</span>}
                            </div>

                            {exec.stdout && (
                              <div>
                                <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.06em] text-[#737373]">
                                  stdout
                                </div>
                                <pre className="max-h-64 overflow-auto rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] p-3 font-mono text-[11.5px] leading-relaxed text-[#141414]">
                                  {exec.stdout}
                                </pre>
                              </div>
                            )}

                            {exec.stderr && (
                              <div>
                                <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.06em] text-[#eb6c36]">
                                  stderr
                                </div>
                                <pre className="max-h-48 overflow-auto rounded-[4px] border border-[#eb6c36]/30 bg-[#fafaf9] p-3 font-mono text-[11.5px] leading-relaxed text-[#525252]">
                                  {exec.stderr}
                                </pre>
                              </div>
                            )}

                            {exec.honeypot_hits && exec.honeypot_hits.length > 0 && (
                              <div className="space-y-1.5 pt-1">
                                {exec.honeypot_hits.map((hit, hIdx) => (
                                  <HoneypotHitAlert key={`${hit.ts}-${hIdx}`} hit={hit} />
                                ))}
                              </div>
                            )}
                          </div>
                        )}

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
                        className="rounded-[6px] border border-[#141414]/[0.14] border-l-2 border-l-[#141414] bg-white p-4"
                      >
                        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="rounded-[3px] border border-[#141414]/40 px-1.5 py-0.5 font-mono text-[10px] font-medium text-[#141414]">
                              REPORTED
                            </span>
                            <span className="font-mono text-xs font-medium text-[#141414]">
                              {item.toolName}
                            </span>
                          </div>
                          <span className="font-mono text-[10.5px] text-[#737373] tabular-nums">
                            turn {item.turn} · seq #{item.seq}
                          </span>
                        </div>
                        {Object.keys(item.argumentsObj).length > 0 && (
                          <pre className="overflow-x-auto rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] p-2.5 font-mono text-[11px] text-[#141414]">
                            {JSON.stringify(item.argumentsObj, null, 2)}
                          </pre>
                        )}
                        {resContent && (
                          <div
                            className={`mt-2 rounded-[4px] border px-3 py-2 font-mono text-[11px] ${
                              isErr
                                ? 'border-[#eb6c36]/50 bg-[#fafaf9] text-[#eb6c36]'
                                : 'border-[#e5e5e5] bg-[#fafaf9] text-[#525252]'
                            }`}
                          >
                            {resContent}
                          </div>
                        )}
                      </article>
                    );
                  }

                  return (
                    <article
                      key={`err-${item.event.seq}-${idx}`}
                      className="rounded-[6px] border border-[#eb6c36] bg-white p-4 text-xs text-[#141414]"
                    >
                      <div className="mb-1 font-mono text-[11px] font-semibold uppercase tracking-[0.04em] text-[#eb6c36]">
                        Episode Error ({String(item.event.payload.where ?? 'runtime')})
                      </div>
                      <pre className="whitespace-pre-wrap font-mono text-[11px] text-[#525252]">
                        {String(item.event.payload.message ?? 'Unknown error')}
                      </pre>
                    </article>
                  );
                })}
              </div>
            </section>

            {/* Final Answer */}
            {traceData.final_answer && (
              <section className="rounded-[6px] border border-[#141414]/[0.14] bg-white p-5">
                <div className="mb-2.5 flex items-center justify-between">
                  <h3 className="font-mono text-[10.5px] font-medium uppercase tracking-[0.08em] text-[#737373]">
                    Final Assistant Answer
                  </h3>
                  <span className="font-mono text-[10.5px] text-[#737373]">
                    status: {traceData.status}
                  </span>
                </div>
                <div className="whitespace-pre-wrap rounded-[4px] border border-[#e5e5e5] bg-[#fafaf9] p-3.5 text-xs leading-relaxed text-[#141414]">
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
