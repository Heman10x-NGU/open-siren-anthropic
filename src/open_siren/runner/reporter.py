"""Static Markdown, JSON, and zero-JS/zero-CDN HTML+SVG reporters for SuiteSummary."""

from __future__ import annotations

import html
from datetime import datetime

from open_siren.types import RateCI, SuiteSummary, SummaryRow


def _fmt_pct(rate_ci: RateCI) -> str:
    if rate_ci.n <= 0:
        return "—"
    return f"{rate_ci.rate * 100:.1f}%"


def _fmt_pct_ci(rate_ci: RateCI) -> str:
    if rate_ci.n <= 0:
        return "—"
    return f"{rate_ci.rate * 100:.1f}% [{rate_ci.lo * 100:.1f}%, {rate_ci.hi * 100:.1f}%]"


def _fmt_reduction(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value * 100:+.1f}%"


def _fmt_timestamp(ts: datetime) -> str:
    return ts.isoformat(timespec="seconds")


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _group_label(row: SummaryRow, group_by: tuple[str, ...]) -> str:
    if not group_by:
        return "all"
    parts = [row.group.get(col, "—") for col in group_by]
    return " / ".join(parts)


def render_json(summary: SuiteSummary) -> str:
    """Serialize SuiteSummary to pretty-printed JSON."""
    return summary.model_dump_json(indent=2) + "\n"


def render_markdown(summary: SuiteSummary) -> str:
    """Render SuiteSummary as a GitHub-flavored Markdown report with a crisp table."""
    group_cols = list(summary.group_by) if summary.group_by else ["Group"]
    headers = [
        *group_cols,
        "N (err)",
        "Reached % [95% CI]",
        "Used %",
        "Misaligned %",
        "Eval-Aware %",
        "Reported %",
        "Feasible Solved %",
        "Reach Reduction vs none",
    ]

    run_ids_str = ", ".join(summary.run_ids) if summary.run_ids else "—"
    lines: list[str] = [
        "# Open Siren Evaluation Summary",
        "",
        (
            f"- **Runs:** {run_ids_str}  \n"
            f"- **Generated:** {_fmt_timestamp(summary.generated_at)}  \n"
            f"- **Schema:** `{summary.schema_version}`"
        ),
        "",
    ]

    if not summary.rows:
        lines.append("_No episodes recorded._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| " + " | ".join(_md_escape(h) for h in headers) + " |")
    align = [":---"] * len(group_cols) + ["---:"] * (len(headers) - len(group_cols))
    lines.append("| " + " | ".join(align) + " |")

    for row in summary.rows:
        if summary.group_by:
            group_vals = [_md_escape(row.group.get(col, "—")) for col in summary.group_by]
        else:
            group_vals = ["all"]
        cells = [
            *group_vals,
            f"{row.n_episodes} ({row.n_errors})",
            _fmt_pct_ci(row.reached),
            _fmt_pct(row.used),
            _fmt_pct(row.misaligned),
            _fmt_pct(row.eval_aware),
            _fmt_pct(row.reported),
            _fmt_pct(row.task_completed_feasible),
            _fmt_reduction(row.reached_reduction_vs_none),
        ]
        lines.append("| " + " | ".join(cells) + " |")

    lines.extend(
        [
            "",
            (
                "_Rates exclude errored episodes. Confidence intervals are 95% Wilson bounds. "
                "Feasible Solved uses feasible tasks only._"
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _render_svg_chart(summary: SuiteSummary) -> str:
    """Build a self-contained inline SVG grouped bar chart with 95% Wilson CI whiskers."""
    svg_width = 880
    left_margin = 240
    right_margin = 100
    top_margin = 52
    bottom_margin = 34
    plot_width = svg_width - left_margin - right_margin

    series: tuple[tuple[str, str, str], ...] = (
        ("reached", "Reached Outside", "#d97706"),
        ("used", "Used", "#ea580c"),
        ("misaligned", "Misaligned Use", "#dc2626"),
    )

    if not summary.rows:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_width} 100" '
            f'role="img" aria-label="Empty evaluation chart" class="chart-svg">'
            f'<text x="{svg_width // 2}" y="55" text-anchor="middle" class="svg-muted">'
            f"No rows to display</text></svg>"
        )

    bar_h = 14
    bar_gap = 5
    group_pad = 22
    group_h = len(series) * bar_h + (len(series) - 1) * bar_gap + group_pad
    svg_height = top_margin + len(summary.rows) * group_h + bottom_margin

    parts: list[str] = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {svg_width} {svg_height}" '
            f'role="img" aria-label="Sandbox escape rates with 95% Wilson confidence intervals" '
            f'class="chart-svg">'
        )
    ]

    # Legend
    legend_x = left_margin
    legend_y = 20
    for _, label, color in series:
        parts.append(
            f'<rect x="{legend_x}" y="{legend_y - 10}" width="12" height="12" '
            f'rx="2" fill="{color}" />'
        )
        parts.append(
            f'<text x="{legend_x + 18}" y="{legend_y}" class="svg-legend">'
            f"{html.escape(label)}</text>"
        )
        legend_x += 18 + len(label) * 7 + 22

    # Whisker legend
    parts.append(
        f'<line x1="{legend_x}" y1="{legend_y - 4}" x2="{legend_x + 16}" y2="{legend_y - 4}" '
        f'class="svg-whisker" />'
        f'<line x1="{legend_x}" y1="{legend_y - 8}" x2="{legend_x}" y2="{legend_y}" '
        f'class="svg-whisker" />'
        f'<line x1="{legend_x + 16}" y1="{legend_y - 8}" x2="{legend_x + 16}" y2="{legend_y}" '
        f'class="svg-whisker" />'
        f'<text x="{legend_x + 22}" y="{legend_y}" class="svg-legend">95% Wilson CI</text>'
    )

    # Vertical grid lines at 0%, 25%, 50%, 75%, 100%
    plot_bottom = top_margin + len(summary.rows) * group_h - group_pad // 2
    for tick in (0, 25, 50, 75, 100):
        x = left_margin + (tick / 100.0) * plot_width
        parts.append(
            f'<line x1="{x:.1f}" y1="{top_margin - 8}" x2="{x:.1f}" y2="{plot_bottom}" '
            f'class="svg-grid" />'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{plot_bottom + 18}" text-anchor="middle" '
            f'class="svg-axis">{tick}%</text>'
        )

    # Group rows and bars
    for row_idx, row in enumerate(summary.rows):
        row_top = top_margin + row_idx * group_h
        bars_block_h = len(series) * bar_h + (len(series) - 1) * bar_gap
        label_y = row_top + bars_block_h / 2 + 4
        raw_label = _group_label(row, summary.group_by)
        display_label = raw_label if len(raw_label) <= 32 else raw_label[:29] + "..."
        parts.append(
            f'<text x="{left_margin - 12}" y="{label_y:.1f}" text-anchor="end" '
            f'class="svg-group-label">'
            f"<title>{html.escape(raw_label)}</title>"
            f"{html.escape(display_label)}</text>"
        )

        for s_idx, (attr_name, series_label, color) in enumerate(series):
            metric: RateCI = getattr(row, attr_name)
            y = row_top + s_idx * (bar_h + bar_gap)
            mid_y = y + bar_h / 2

            if metric.n <= 0:
                parts.append(
                    f'<text x="{left_margin + 6}" y="{mid_y + 4:.1f}" class="svg-muted">N/A</text>'
                )
                continue

            bar_w = max(0.0, min(1.0, metric.rate)) * plot_width
            lo_x = left_margin + max(0.0, min(1.0, metric.lo)) * plot_width
            hi_x = left_margin + max(0.0, min(1.0, metric.hi)) * plot_width
            tooltip = (
                f"{raw_label} — {series_label}: {metric.rate * 100:.1f}% "
                f"({metric.k}/{metric.n}, 95% CI [{metric.lo * 100:.1f}%, {metric.hi * 100:.1f}%])"
            )

            parts.append(
                f'<rect x="{left_margin}" y="{y}" width="{max(bar_w, 1.5):.1f}" '
                f'height="{bar_h}" rx="3" fill="{color}" opacity="0.88">'
                f"<title>{html.escape(tooltip)}</title></rect>"
            )

            # 95% Wilson CI whisker + end caps
            parts.append(
                f'<line x1="{lo_x:.1f}" y1="{mid_y:.1f}" x2="{hi_x:.1f}" y2="{mid_y:.1f}" '
                f'class="svg-whisker" />'
                f'<line x1="{lo_x:.1f}" y1="{mid_y - 3.5:.1f}" x2="{lo_x:.1f}" '
                f'y2="{mid_y + 3.5:.1f}" class="svg-whisker" />'
                f'<line x1="{hi_x:.1f}" y1="{mid_y - 3.5:.1f}" x2="{hi_x:.1f}" '
                f'y2="{mid_y + 3.5:.1f}" class="svg-whisker" />'
            )

            label_x = max(left_margin + bar_w, hi_x) + 8
            parts.append(
                f'<text x="{label_x:.1f}" y="{mid_y + 4:.1f}" class="svg-value">'
                f"{metric.rate * 100:.1f}% ({metric.k}/{metric.n})</text>"
            )

    parts.append("</svg>")
    return "\n".join(parts)


def render_html(summary: SuiteSummary) -> str:
    """Render SuiteSummary as a self-contained static HTML page (zero JS, zero CDN links)."""
    group_cols = list(summary.group_by) if summary.group_by else ["Group"]
    headers = [
        *group_cols,
        "N (err)",
        "Reached % [95% CI]",
        "Used %",
        "Misaligned %",
        "Eval-Aware %",
        "Reported %",
        "Feasible Solved %",
        "Reach Reduction vs none",
    ]

    header_html = "".join(
        f'<th class="{"num" if idx >= len(group_cols) else "txt"}">{html.escape(h)}</th>'
        for idx, h in enumerate(headers)
    )

    body_rows: list[str] = []
    for row in summary.rows:
        if summary.group_by:
            group_cells = [
                f'<td class="txt">{html.escape(row.group.get(col, "—"))}</td>'
                for col in summary.group_by
            ]
        else:
            group_cells = ['<td class="txt">all</td>']

        metric_cells = [
            f'<td class="num">{row.n_episodes} ({row.n_errors})</td>',
            f'<td class="num">{html.escape(_fmt_pct_ci(row.reached))}</td>',
            f'<td class="num">{html.escape(_fmt_pct(row.used))}</td>',
            f'<td class="num">{html.escape(_fmt_pct(row.misaligned))}</td>',
            f'<td class="num">{html.escape(_fmt_pct(row.eval_aware))}</td>',
            f'<td class="num">{html.escape(_fmt_pct(row.reported))}</td>',
            f'<td class="num">{html.escape(_fmt_pct(row.task_completed_feasible))}</td>',
            f'<td class="num">{html.escape(_fmt_reduction(row.reached_reduction_vs_none))}</td>',
        ]
        body_rows.append("<tr>" + "".join(group_cells + metric_cells) + "</tr>")

    if not body_rows:
        body_rows.append(
            f'<tr><td colspan="{len(headers)}" class="empty">No episodes recorded.</td></tr>'
        )

    total_episodes = sum(r.n_episodes for r in summary.rows)
    total_errors = sum(r.n_errors for r in summary.rows)
    run_ids_str = ", ".join(summary.run_ids) if summary.run_ids else "—"
    chart_svg = _render_svg_chart(summary)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Open Siren Evaluation Report</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #475569;
      --border: #e2e8f0;
      --grid: #e2e8f0;
      --whisker: #1e293b;
      --row-alt: #f8fafc;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b1120;
        --card: #111827;
        --text: #f1f5f9;
        --muted: #94a3b8;
        --border: #1f2937;
        --grid: #273244;
        --whisker: #e2e8f0;
        --row-alt: #0f172a;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 2rem 1.25rem;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      display: grid;
      gap: 1.5rem;
    }}
    header h1 {{
      margin: 0 0 0.35rem 0;
      font-size: 1.5rem;
      letter-spacing: -0.01em;
    }}
    .meta {{
      color: var(--muted);
      font-size: 0.9rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.5rem;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
    }}
    .card h2 {{
      margin: 0 0 0.85rem 0;
      font-size: 1.05rem;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
      font-variant-numeric: tabular-nums;
    }}
    th, td {{
      padding: 0.55rem 0.7rem;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      text-align: left;
    }}
    th.num, td.num {{
      text-align: right;
    }}
    tbody tr:nth-child(even) {{
      background: var(--row-alt);
    }}
    td.empty {{
      text-align: center;
      color: var(--muted);
      padding: 1.5rem;
    }}
    .chart-svg {{
      width: 100%;
      height: auto;
      display: block;
    }}
    .svg-legend {{
      fill: var(--text);
      font-size: 12px;
      font-weight: 500;
    }}
    .svg-group-label {{
      fill: var(--text);
      font-size: 12px;
      font-weight: 600;
    }}
    .svg-axis, .svg-muted {{
      fill: var(--muted);
      font-size: 11px;
    }}
    .svg-value {{
      fill: var(--text);
      font-size: 11px;
      font-variant-numeric: tabular-nums;
    }}
    .svg-grid {{
      stroke: var(--grid);
      stroke-width: 1;
      stroke-dasharray: 3 3;
    }}
    .svg-whisker {{
      stroke: var(--whisker);
      stroke-width: 1.5;
      stroke-linecap: round;
    }}
    footer {{
      color: var(--muted);
      font-size: 0.82rem;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Open Siren Evaluation Report</h1>
      <div class="meta">
        <span><strong>Runs:</strong> {html.escape(run_ids_str)}</span>
        <span><strong>Episodes:</strong> {total_episodes} ({total_errors} errors)</span>
        <span><strong>Generated:</strong> {html.escape(_fmt_timestamp(summary.generated_at))}</span>
        <span><strong>Schema:</strong> {html.escape(summary.schema_version)}</span>
      </div>
    </header>
    <section class="card">
      <h2>Escape &amp; Misalignment Rates (95% Wilson CI)</h2>
      {chart_svg}
    </section>
    <section class="card">
      <h2>Summary Table</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>{header_html}</tr>
          </thead>
          <tbody>
            {"".join(body_rows)}
          </tbody>
        </table>
      </div>
    </section>
    <footer>
      Rates exclude errored episodes. Whiskers show 95% Wilson confidence intervals.
      Feasible Solved uses feasible tasks only.
    </footer>
  </main>
</body>
</html>
"""
