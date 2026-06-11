"""
THE REPORT.

Turns the same quality checks used by the translator into a clean, shareable
HTML page a non-technical person can read: one row per column, a red/amber/green
health badge, the detected traps, and suggested fixes.

This reuses the SAME detection logic as the translator (one source of truth),
so the report and the AI-summary never disagree.

    import safedata
    safedata.report(df, "report.html")   # writes a file you can open/share
    html = safedata.report(df)            # or get the HTML string back
"""

import html as _html
import pandas as pd

from .translator import (_trap_warnings, HIGH_MISSING_THRESHOLD, _fmt_missing,
                         dedupe_columns)


def _severity_for_column(df, col, trap_text):
    """Pick a red/amber/green status for a column based on findings."""
    null_frac = df[col].isna().mean()
    mentioned = f"'{col}'" in trap_text

    if null_frac >= 1.0 or (mentioned and ("TEXT but holds numbers" in trap_text
                                           or "SERIAL DATE" in trap_text
                                           or "NOT unique" in trap_text)):
        return "red", "Needs attention"
    if null_frac >= HIGH_MISSING_THRESHOLD or mentioned:
        return "amber", "Check this"
    return "green", "Looks OK"


def _build_html(df: pd.DataFrame) -> str:
    # Make column names unique first; otherwise df[col] returns a DataFrame and
    # every per-column check below (isna().mean(), severity) raises. Mirrors the
    # text summary, which de-duplicates the same way.
    df, dup_names = dedupe_columns(df)

    warnings = _trap_warnings(df)
    if dup_names:
        shown = ", ".join(f"'{c}'" for c in dup_names[:6])
        more = f" (+{len(dup_names) - 6} more)" if len(dup_names) > 6 else ""
        warnings.insert(0,
            f"{len(dup_names)} column name(s) are DUPLICATED ({shown}{more}); "
            f"they were renamed with a numeric suffix for analysis. Fix the "
            f"source so each column has a unique name.")
    trap_blob = "\n".join(warnings)

    n_red = n_amber = n_green = 0
    rows_html = []
    for col in df.columns:
        sev, label = _severity_for_column(df, col, trap_blob)
        if sev == "red":
            n_red += 1
        elif sev == "amber":
            n_amber += 1
        else:
            n_green += 1

        dtype = _html.escape(str(df[col].dtype))
        null_frac = df[col].isna().mean()
        null_disp = _fmt_missing(null_frac)

        # Per-row notes: only column-specific traps, EXCLUDING the long grouped
        # "N column(s) are mostly empty..." sentence (shown once at the top).
        col_traps = [w for w in warnings
                     if f"'{col}'" in w and "column(s)" not in w]
        if null_frac >= HIGH_MISSING_THRESHOLD:
            col_traps.insert(0, f"Mostly empty ({null_disp} missing); "
                                f"consider dropna() before using this column.")
        traps_disp = "<br>".join(_html.escape(t) for t in col_traps) or "&mdash;"

        rows_html.append(f"""
          <tr class="{sev}">
            <td class="col-name">{_html.escape(str(col))}</td>
            <td><span class="badge {sev}">{label}</span></td>
            <td>{dtype}</td>
            <td>{null_disp}</td>
            <td class="traps">{traps_disp}</td>
          </tr>""")

    # warnings that aren't tied to one column (grouped lines) shown up top
    general = [w for w in warnings
               if not any(f"'{c}'" in w for c in df.columns)
               or "column(s)" in w]
    general_html = ""
    if general:
        items = "".join(f"<li>{_html.escape(w)}</li>" for w in general)
        general_html = f"""
        <div class="general">
          <h2>Summary findings</h2>
          <ul>{items}</ul>
        </div>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>safedata report</title>
<style>
  :root {{
    --red: #c0392b; --amber: #b9770e; --green: #1e8449;
    --redbg: #fdecea; --amberbg: #fef5e7; --greenbg: #eafaf1;
    --ink: #1a1a2e; --muted: #6b7280; --line: #e5e7eb;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         color: var(--ink); margin: 0; padding: 32px; background: #fafafa; }}
  h1 {{ margin: 0 0 4px; font-size: 24px; }}
  .sub {{ color: var(--muted); margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ flex: 1; min-width: 120px; padding: 16px; border-radius: 10px;
          border: 1px solid var(--line); background: #fff; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card.red .num {{ color: var(--red); }}
  .card.amber .num {{ color: var(--amber); }}
  .card.green .num {{ color: var(--green); }}
  .card .lbl {{ color: var(--muted); font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line);
           font-size: 14px; vertical-align: top; }}
  th {{ background: #f3f4f6; font-weight: 600; }}
  .col-name {{ font-weight: 600; }}
  .traps {{ color: var(--muted); font-size: 13px; }}
  .badge {{ padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
  .badge.red {{ background: var(--redbg); color: var(--red); }}
  .badge.amber {{ background: var(--amberbg); color: var(--amber); }}
  .badge.green {{ background: var(--greenbg); color: var(--green); }}
  .general {{ background: #fff; border: 1px solid var(--line); border-radius: 10px;
             padding: 16px 20px; margin-bottom: 24px; }}
  .general h2 {{ margin: 0 0 8px; font-size: 16px; }}
  .general li {{ margin: 4px 0; font-size: 14px; }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 24px; }}
</style></head>
<body>
  <h1>Data quality report</h1>
  <div class="sub">{len(df):,} rows &times; {df.shape[1]} columns</div>
  <div class="cards">
    <div class="card red"><div class="num">{n_red}</div><div class="lbl">Needs attention</div></div>
    <div class="card amber"><div class="num">{n_amber}</div><div class="lbl">Check this</div></div>
    <div class="card green"><div class="num">{n_green}</div><div class="lbl">Looks OK</div></div>
  </div>
  {general_html}
  <table>
    <thead><tr><th>Column</th><th>Status</th><th>Type</th><th>Missing</th><th>Notes</th></tr></thead>
    <tbody>{''.join(rows_html)}</tbody>
  </table>
  <footer>Generated by safedata-guard. Findings are heuristics; verify before acting.</footer>
</body></html>"""


def report(df: pd.DataFrame, path: str = None) -> str:
    """
    Build a shareable HTML data-quality report for `df`.

    If `path` is given, writes the HTML there and returns the path.
    Otherwise returns the HTML as a string.
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("safedata.report expects a pandas DataFrame, "
                        f"got {type(df).__name__}")
    html_str = _build_html(df)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_str)
        return path
    return html_str
