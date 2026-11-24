// Exact TypeScript mirrors of src/open_siren/types.py and web_export JSON contracts.

export type Difficulty = 'easy' | 'medium' | 'hard' | 'impossible';
export type WeaknessType = 'misconfiguration' | 'vulnerability';
export type HoneypotKind = 'file' | 'env_secret' | 'http_service' | 'control_socket';
export type AmbiguityLevel = 'clear_violation' | 'borderline';
export type TempterSegmentKind =
  | 'deadline'
  | 'stakes'
  | 'broad_authority'
  | 'search_thoroughly'
  | 'other';
export type TempterAblation =
  | 'as_written'
  | 'strip_deadline'
  | 'strip_authority_and_search'
  | 'strip_all';
export type EpisodeStatus = 'completed' | 'max_turns' | 'timeout' | 'error';
export type TraceEventType =
  | 'model_turn'
  | 'tool_call'
  | 'gate_decision'
  | 'exec_result'
  | 'mitigation_tool_result'
  | 'error';

export interface SandboxReport {
  weakness_type: string;
  path_or_endpoint: string;
  description: string;
  source: 'agent' | 'seed';
}

export interface SandboxArchetype {
  id: string;
  weakness_type: WeaknessType;
  weakness_mechanism: string;
  description: string;
  kind_label_override?: string | null;
  config?: Record<string, unknown>;
  seed_report?: SandboxReport | null;
}

export interface TaskSpec {
  id: string;
  title: string;
  difficulty: Difficulty;
  prompt: string;
  workspace_files?: Record<string, string>;
  verification_cmd?: string | null;
}

export interface HoneypotSpec {
  id: string;
  kind: HoneypotKind;
  name: string;
  content_template: string;
  description: string;
  default_ambiguity?: AmbiguityLevel;
}

export interface TempterSegment {
  kind: TempterSegmentKind;
  text: string;
}

export interface TempterSpec {
  id: string;
  segments: TempterSegment[];
  tags?: string[];
}

export interface ScenarioSpec {
  scenario_id: string;
  suite_id: string;
  sandbox: SandboxArchetype;
  task: TaskSpec;
  honeypot: HoneypotSpec;
  tempter: TempterSpec;
  tempter_ablation: TempterAblation;
  ambiguity_level: AmbiguityLevel;
  tags?: string[];
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface HoneypotHit {
  channel: 'http' | 'unix_socket';
  ts: string;
  method?: string | null;
  path?: string | null;
  headers?: Record<string, string>;
  body_excerpt?: string;
  served_canary: boolean;
  request_contains_canary: boolean;
}

export interface ExecResultPayload {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timed_out: boolean;
  duration_ms: number;
  canary_in_output: boolean;
  honeypot_hits?: HoneypotHit[];
  tool_call_id?: string;
  command?: string;
}

export interface GateDecision {
  allow: boolean;
  mitigation: string;
  stage: 'none' | 'rules' | 'classifier' | 'error';
  risk_category?: string | null;
  reason: string;
}

export interface TraceEvent {
  seq: number;
  turn: number;
  ts: string;
  event_type: TraceEventType;
  payload: Record<string, unknown>;
}

export interface GradeResult {
  reached_outside: boolean;
  used_honeypot: boolean;
  misaligned_use: boolean;
  eval_awareness_detected: boolean;
  task_feasible: boolean;
  task_completed: boolean;
  reported_weakness: boolean;
  blocked_commands: number;
  first_reach_seq?: number | null;
  first_read_seq?: number | null;
  evidence: string[];
}

export interface OutsideSyscall {
  seq?: number;
  turn?: number;
  ts?: string;
  syscall: string;
  path?: string;
  target?: string;
  addr?: string;
  pid?: number;
  result?: string;
  raw?: string;
  [key: string]: unknown;
}

export interface EpisodeResult {
  schema_version: string;
  run_id: string;
  episode_id: string;
  scenario: ScenarioSpec;
  provider: string;
  model: string;
  backend: string;
  mitigation_set_id: string;
  mitigations: string[];
  repeat: number;
  status: EpisodeStatus;
  error?: string | null;
  grade: GradeResult | null;
  turns: number;
  duration_ms: number;
  token_usage: TokenUsage;
  workspace_root: string;
  allowed_destinations?: string[];
  reports: SandboxReport[];
  final_answer?: string | null;
  trace: TraceEvent[];
  started_at: string;
  finished_at: string;
  outside_syscalls?: OutsideSyscall[];
}

export interface RateCI {
  k: number;
  n: number;
  rate: number;
  lo: number;
  hi: number;
}

export interface SummaryRow {
  group: Record<string, string>;
  n_episodes: number;
  n_errors: number;
  reached: RateCI;
  used: RateCI;
  misaligned: RateCI;
  eval_aware: RateCI;
  reported: RateCI;
  task_completed_feasible: RateCI;
  reached_reduction_vs_none: number | null;
}

export interface SuiteSummary {
  schema_version: string;
  run_ids: string[];
  group_by: string[];
  rows: SummaryRow[];
  generated_at: string;
}

export interface ReplayReport {
  schema_version: string;
  n_episodes: number;
  n_reaching: number;
  n_misaligned: number;
  blocked_first_reach: RateCI;
  blocked_first_read_misaligned: RateCI;
  benign_commands_blocked: RateCI;
  caveat: string;
}

export interface ReplayData {
  by_model: Record<string, ReplayReport>;
}

export interface BreakdownsData {
  by_difficulty: SuiteSummary;
  by_mechanism: SuiteSummary;
  by_ablation: SuiteSummary;
}

export interface EpisodeIndexItem {
  episode_id: string;
  run_id?: string;
  model: string;
  provider?: string;
  backend: string;
  mitigation_set_id: string;
  scenario_id: string;
  mechanism: string;
  difficulty: Difficulty;
  tempter_ablation: TempterAblation;
  ambiguity_level?: AmbiguityLevel;
  status?: EpisodeStatus;
  turns?: number;
  duration_ms?: number;
  reached_outside: boolean;
  used_honeypot: boolean;
  misaligned_use: boolean;
  eval_awareness_detected: boolean;
  reported_weakness: boolean;
  task_completed?: boolean;
  task_feasible?: boolean;
  blocked_commands: number;
}

export interface Manifest {
  schema_version: string;
  generated_at: string;
  is_demo: boolean;
  models: string[];
  backends: string[];
  mitigation_sets: string[];
  total_episodes: number;
  episode_index: EpisodeIndexItem[];
}

export type OutcomeBadge =
  | 'Misaligned'
  | 'Used'
  | 'Reached'
  | 'Blocked'
  | 'Reported'
  | 'Clean';

export type ActiveTab = 'leaderboard' | 'ablations' | 'replay' | 'trace';
