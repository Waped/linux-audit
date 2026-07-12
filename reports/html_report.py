"""
html_report.py — Génération du rapport HTML auto-contenu
Le rapport est lisible dans n'importe quel navigateur sans dépendance externe.
"""

from pathlib import Path


SEVERITY_COLOR = {
    "HIGH":   ("#ef4444", "#fef2f2", "🔴"),
    "MEDIUM": ("#f59e0b", "#fffbeb", "🟡"),
    "LOW":    ("#3b82f6", "#eff6ff", "🔵"),
}


def _score_color(score: int) -> str:
    if score >= 80:
        return "#22c55e"
    elif score >= 50:
        return "#f59e0b"
    return "#ef4444"


def _score_label(score: int) -> str:
    if score >= 80:
        return "Conforme"
    elif score >= 50:
        return "À améliorer"
    return "Critique"


def _finding_card(f: dict) -> str:
    severity = f.get("severity", "LOW")
    color, bg, icon = SEVERITY_COLOR.get(severity, ("#6b7280", "#f9fafb", "⚪"))
    refs_html = ""
    if f.get("references"):
        refs_html = "<div class='refs'>📚 " + " &nbsp;|&nbsp; ".join(
            f"<code>{r}</code>" for r in f["references"]
        ) + "</div>"

    return f"""
    <div class="finding-card" style="border-left: 4px solid {color}; background:{bg};">
      <div class="finding-header">
        <span class="badge" style="background:{color};">{icon} {severity}</span>
        <span class="finding-id">{f.get('id','')}</span>
        <strong>{f.get('title','')}</strong>
      </div>
      <p class="finding-desc">{f.get('description','').replace(chr(10), '<br>')}</p>
      <div class="remediation">
        <strong>✅ Remédiation :</strong><br>
        {f.get('remediation','').replace(chr(10), '<br>')}
      </div>
      {refs_html}
    </div>"""


def generate_html_report(report: dict) -> str:
    meta    = report["meta"]
    summary = report["summary"]
    cats    = report["categories"]

    score       = summary["score"]
    s_color     = _score_color(score)
    s_label     = _score_label(score)
    by_sev      = summary["by_severity"]
    total       = summary["total_findings"]

    # ── Catégories ──────────────────────────────────────────────────
    categories_html = ""
    for cat in cats:
        name     = cat.get("category", "")
        findings = cat.get("findings", [])
        status   = "✅ Aucun problème" if not findings else f"⚠️ {len(findings)} finding(s)"
        finding_cards = "".join(_finding_card(f) for f in findings) if findings else \
                        "<p class='ok-msg'>✅ Aucun problème détecté dans cette catégorie.</p>"
        categories_html += f"""
        <section class="category">
          <div class="cat-header">
            <h2>{name}</h2>
            <span class="cat-status">{status}</span>
          </div>
          {finding_cards}
        </section>"""

    # ── Tableau de bord ─────────────────────────────────────────────
    dashboard = f"""
    <div class="dashboard">
      <div class="score-card">
        <div class="score-ring" style="--score-color:{s_color};">
          <span class="score-value" style="color:{s_color};">{score}</span>
          <span class="score-max">/100</span>
        </div>
        <div class="score-label" style="color:{s_color};">{s_label}</div>
      </div>
      <div class="stats-grid">
        <div class="stat-card high">
          <span class="stat-num">{by_sev.get('HIGH',0)}</span>
          <span class="stat-label">🔴 Critique</span>
        </div>
        <div class="stat-card medium">
          <span class="stat-num">{by_sev.get('MEDIUM',0)}</span>
          <span class="stat-label">🟡 Modéré</span>
        </div>
        <div class="stat-card low">
          <span class="stat-num">{by_sev.get('LOW',0)}</span>
          <span class="stat-label">🔵 Faible</span>
        </div>
        <div class="stat-card total">
          <span class="stat-num">{total}</span>
          <span class="stat-label">Total findings</span>
        </div>
      </div>
    </div>"""

    # ── Meta info ────────────────────────────────────────────────────
    meta_html = f"""
    <div class="meta-bar">
      <span>🖥️ <strong>{meta.get('hostname','')}</strong></span>
      <span>📅 {meta.get('timestamp','')[:19].replace('T',' ')}</span>
      <span>🐧 {meta.get('os','')}</span>
      <span>🔧 {meta.get('tool','')}</span>
    </div>"""

    # ── HTML complet ─────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LinuxAudit – Rapport de sécurité</title>
  <style>
    :root {{
      --bg:      #0f172a;
      --surface: #1e293b;
      --border:  #334155;
      --text:    #e2e8f0;
      --muted:   #94a3b8;
      --accent:  #38bdf8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }}

    /* ── Header ─────────────────────────────────────── */
    header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      border-bottom: 1px solid var(--border);
      padding: 2rem;
      display: flex;
      align-items: center;
      gap: 1.5rem;
    }}
    .logo {{
      font-size: 2.5rem;
      filter: drop-shadow(0 0 8px var(--accent));
    }}
    header h1 {{
      font-size: 1.8rem;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: -0.5px;
    }}
    header p {{ color: var(--muted); font-size: 0.9rem; }}

    /* ── Meta bar ────────────────────────────────────── */
    .meta-bar {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 2rem;
      display: flex;
      gap: 2rem;
      flex-wrap: wrap;
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .meta-bar strong {{ color: var(--text); }}

    /* ── Main ────────────────────────────────────────── */
    main {{ max-width: 1100px; margin: 2rem auto; padding: 0 2rem 4rem; }}

    /* ── Dashboard ───────────────────────────────────── */
    .dashboard {{
      display: flex;
      gap: 1.5rem;
      align-items: center;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 2.5rem;
      flex-wrap: wrap;
    }}
    .score-card {{
      display: flex;
      flex-direction: column;
      align-items: center;
      min-width: 130px;
    }}
    .score-ring {{
      width: 110px; height: 110px;
      border-radius: 50%;
      border: 8px solid var(--score-color, #6b7280);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px color-mix(in srgb, var(--score-color, gray) 40%, transparent);
    }}
    .score-value {{ font-size: 2.2rem; font-weight: 800; line-height: 1; }}
    .score-max   {{ font-size: 0.75rem; color: var(--muted); }}
    .score-label {{ margin-top: 0.5rem; font-weight: 600; font-size: 0.9rem; }}

    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      flex: 1;
    }}
    .stat-card {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }}
    .stat-num   {{ display: block; font-size: 2rem; font-weight: 800; line-height: 1; }}
    .stat-label {{ display: block; font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; }}
    .stat-card.high   .stat-num {{ color: #ef4444; }}
    .stat-card.medium .stat-num {{ color: #f59e0b; }}
    .stat-card.low    .stat-num {{ color: #3b82f6; }}
    .stat-card.total  .stat-num {{ color: var(--accent); }}

    /* ── Categories ──────────────────────────────────── */
    .category {{
      margin-bottom: 2rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }}
    .cat-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 1.5rem;
      background: rgba(255,255,255,0.03);
      border-bottom: 1px solid var(--border);
    }}
    .cat-header h2 {{ font-size: 1rem; font-weight: 600; color: var(--accent); }}
    .cat-status    {{ font-size: 0.8rem; color: var(--muted); }}

    /* ── Finding cards ───────────────────────────────── */
    .finding-card {{
      margin: 1rem;
      padding: 1rem 1.25rem;
      border-radius: 8px;
      border-left-width: 4px;
      border-left-style: solid;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
      flex-wrap: wrap;
    }}
    .badge {{
      font-size: 0.7rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 9999px;
      color: white;
      white-space: nowrap;
    }}
    .finding-id {{ font-size: 0.75rem; color: #64748b; font-family: monospace; }}
    .finding-header strong {{ color: #1e293b; font-size: 0.95rem; }}
    .finding-desc {{
      font-size: 0.875rem;
      color: #374151;
      margin-bottom: 0.75rem;
      font-family: monospace;
      white-space: pre-wrap;
    }}
    .remediation {{
      background: rgba(255,255,255,0.6);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
      color: #1e293b;
    }}
    .remediation strong {{ color: #065f46; }}
    .refs {{
      margin-top: 0.5rem;
      font-size: 0.75rem;
      color: #6b7280;
    }}
    .refs code {{
      background: rgba(0,0,0,0.08);
      padding: 1px 5px;
      border-radius: 3px;
    }}
    .ok-msg {{
      padding: 1rem 1.5rem;
      color: #16a34a;
      font-size: 0.9rem;
    }}

    /* ── Footer ──────────────────────────────────────── */
    footer {{
      text-align: center;
      padding: 2rem;
      color: var(--muted);
      font-size: 0.8rem;
      border-top: 1px solid var(--border);
    }}

    @media (max-width: 768px) {{
      .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
      .dashboard  {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <header>
    <span class="logo">🛡️</span>
    <div>
      <h1>LinuxAudit – Rapport de Sécurité</h1>
      <p>Audit automatisé de conformité Linux | EFREI Mastère Cybersécurité & Cloud</p>
    </div>
  </header>

  {meta_html}

  <main>
    {dashboard}
    {categories_html}
  </main>

  <footer>
    Généré par <strong>LinuxAudit v1.0</strong> · {meta.get('author','')} ·
    Référentiels : CIS Benchmark Linux, ANSSI Recommandations, ISO 27001
  </footer>
</body>
</html>"""
