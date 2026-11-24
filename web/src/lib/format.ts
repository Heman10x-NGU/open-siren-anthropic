import type { EpisodeIndexItem, OutcomeBadge, RateCI } from '../types';

export function dataUrl(relPath: string): string {
  const base = import.meta.env.BASE_URL || '/';
  const normalizedBase = base.endsWith('/') ? base : `${base}/`;
  const cleanRel = relPath.replace(/^\/+/, '');
  return `${normalizedBase}data/${cleanRel}`;
}

export function fmtPct(metric: RateCI | null | undefined, digits = 1): string {
  if (!metric || metric.n <= 0) return '—';
  return `${(metric.rate * 100).toFixed(digits)}%`;
}

export function fmtCI(metric: RateCI | null | undefined, digits = 1): string {
  if (!metric || metric.n <= 0) return '';
  return `[${(metric.lo * 100).toFixed(digits)}%, ${(metric.hi * 100).toFixed(digits)}%]`;
}

export function fmtReduction(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  const pct = value * 100;
  const sign = pct > 0 ? '-' : pct < 0 ? '+' : '';
  // Note: aggregator defines reduction = (base - rate) / base, so positive = reduction in escape rate
  // We format positive as "-62.5%" (drop in reach rate) or keep signed with clarity
  return `${sign}${Math.abs(pct).toFixed(1)}%`;
}

export function fmtDuration(ms: number | undefined): string {
  if (ms === undefined || ms === null) return '—';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.round((ms % 60_000) / 1000);
  return `${mins}m ${secs}s`;
}

export function fmtTimestamp(iso: string | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

export function fmtTokens(n: number | undefined): string {
  if (n === undefined || n === null) return '0';
  return n.toLocaleString('en-US');
}

export const DIFFICULTY_ORDER = ['easy', 'medium', 'hard', 'impossible'] as const;

export const MECHANISM_ORDER = [
  'host_mount_leak',
  'control_socket_leak',
  'loopback_service_leak',
  'env_proc_leak',
  'egress_proxy_bypass',
  'fd_leak',
] as const;

export const ABLATION_ORDER = [
  'as_written',
  'strip_deadline',
  'strip_authority_and_search',
  'strip_all',
] as const;

export const MITIGATION_ORDER = [
  'none',
  'sandbox_rules',
  'report_tools',
  'report_tools+view_reports',
  'auto_gate',
  'all',
] as const;

export const MECHANISM_LABELS: Record<string, string> = {
  host_mount_leak: 'Host Mount Leak',
  control_socket_leak: 'Control Socket Leak',
  loopback_service_leak: 'Loopback Service Leak',
  env_proc_leak: 'Env / Proc Leak',
  egress_proxy_bypass: 'Egress Proxy Bypass',
  fd_leak: 'Inherited FD Leak',
};

export const ABLATION_LABELS: Record<string, string> = {
  as_written: 'As Written (Full Tempter)',
  strip_deadline: 'Strip Deadline',
  strip_authority_and_search: 'Strip Authority & Search',
  strip_all: 'Strip All (Task Only)',
};

export const DIFFICULTY_LABELS: Record<string, string> = {
  easy: 'Easy',
  medium: 'Medium',
  hard: 'Hard',
  impossible: 'Impossible',
};

export function labelForMechanism(mech: string): string {
  return MECHANISM_LABELS[mech] ?? mech.replace(/_/g, ' ');
}

export function labelForAblation(ablation: string): string {
  return ABLATION_LABELS[ablation] ?? ablation.replace(/_/g, ' ');
}

export function labelForDifficulty(diff: string): string {
  return DIFFICULTY_LABELS[diff] ?? diff;
}

export function getEpisodeOutcomeBadges(ep: EpisodeIndexItem): OutcomeBadge[] {
  const badges: OutcomeBadge[] = [];
  if (ep.misaligned_use) badges.push('Misaligned');
  else if (ep.used_honeypot) badges.push('Used');
  else if (ep.reached_outside) badges.push('Reached');

  if (ep.blocked_commands > 0) badges.push('Blocked');
  if (ep.reported_weakness) badges.push('Reported');

  if (!ep.reached_outside && !ep.used_honeypot && !ep.misaligned_use) {
    badges.push('Clean');
  }
  return badges;
}

export function primaryOutcomeBadge(ep: EpisodeIndexItem): OutcomeBadge {
  if (ep.misaligned_use) return 'Misaligned';
  if (ep.used_honeypot) return 'Used';
  if (ep.reached_outside) return 'Reached';
  if (ep.blocked_commands > 0) return 'Blocked';
  if (ep.reported_weakness) return 'Reported';
  return 'Clean';
}

export function outcomeBadgeStyle(badge: OutcomeBadge): string {
  switch (badge) {
    case 'Misaligned':
      return 'bg-red-500/15 text-red-400 border-red-500/30';
    case 'Used':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    case 'Reached':
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    case 'Blocked':
      return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    case 'Reported':
      return 'bg-teal-500/15 text-teal-300 border-teal-500/30';
    case 'Clean':
      return 'bg-zinc-800/80 text-zinc-300 border-zinc-700/70';
  }
}
