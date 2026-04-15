import csv
import json
from pathlib import Path
from html import escape


def save_json_report(report, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def render_text_report(report):
    headers = report.get("headers", {})
    assessment = report.get("assessment", {})
    urls = report.get("urls", [])
    attachments = report.get("attachments", [])
    keyword_hits = report.get("keyword_hits", [])
    reasons = assessment.get("reasons", [])

    lines = [
        "========== PHISHING EMAIL ANALYZER ==========",
        f"File: {report.get('file_analyzed', '')}",
        f"Subject: {headers.get('subject', '')}",
        f"From: {headers.get('from', '')}",
        f"To: {headers.get('to', '')}",
        f"Date: {headers.get('date', '')}",
        f"Reply-To: {headers.get('reply_to', '')}",
        f"Return-Path: {headers.get('return_path', '')}",
        "",
        "---------- ASSESSMENT ----------",
        f"Risk Score: {assessment.get('score', 0)}",
        f"Verdict: {assessment.get('verdict', 'UNKNOWN')}",
        "",
        "---------- URLS ----------",
    ]

    if urls:
        for item in urls:
            lines.append(f"- {item.get('url', '')} | domain={item.get('domain', '')}")
    else:
        lines.append("- None")

    lines.extend(["", "---------- ATTACHMENTS ----------"])
    if attachments:
        for item in attachments:
            line = f"- {item.get('filename', '')} | ext={item.get('extension', '')} | size={item.get('size_bytes', 0)}"
            vt = item.get("virustotal", {})
            if vt:
                line += f" | VT={vt.get('status', '')}"
                if vt.get("status") == "found":
                    line += f" | malicious={vt.get('malicious', 0)} | suspicious={vt.get('suspicious', 0)}"
            lines.append(line)
    else:
        lines.append("- None")

    lines.extend(["", "---------- KEYWORDS ----------"])
    if keyword_hits:
        for word in keyword_hits:
            lines.append(f"- {word}")
    else:
        lines.append("- None")

    lines.extend(["", "---------- REASONS ----------"])
    if reasons:
        for reason in reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- None")

    return "\n".join(lines)


def save_text_report(report, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_text_report(report), encoding="utf-8")


def save_csv_summary(reports, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "file_analyzed",
        "subject",
        "from",
        "sender_domain",
        "verdict",
        "score",
        "url_count",
        "attachment_count",
        "keyword_count",
        "reason_summary"
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for report in reports:
            writer.writerow({
                "file_analyzed": report.get("file_analyzed", ""),
                "subject": report.get("headers", {}).get("subject", ""),
                "from": report.get("headers", {}).get("from", ""),
                "sender_domain": report.get("sender_domain", ""),
                "verdict": report.get("assessment", {}).get("verdict", ""),
                "score": report.get("assessment", {}).get("score", 0),
                "url_count": len(report.get("urls", [])),
                "attachment_count": len(report.get("attachments", [])),
                "keyword_count": len(report.get("keyword_hits", [])),
                "reason_summary": " | ".join(report.get("assessment", {}).get("reasons", []))
            })


def save_html_summary(reports, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    def verdict_class(verdict):
        v = (verdict or "").upper()
        if v == "HIGH":
            return "high"
        if v == "MEDIUM":
            return "medium"
        return "low"

    def score_bar(score):
        pct = min(int(score), 100)
        if pct >= 70:
            color = "#ff3b3b"
        elif pct >= 40:
            color = "#ffb300"
        else:
            color = "#00e676"
        return f"""
        <div class="score-wrap">
            <span class="score-num">{score}</span>
            <div class="score-bar-bg">
                <div class="score-bar-fill" style="width:{pct}%;background:{color};"></div>
            </div>
        </div>"""

    def tag_list(items, cls="tag"):
        if not items:
            return '<span class="none-label">—</span>'
        return "".join(f'<span class="{cls}">{escape(str(i))}</span>' for i in items)

    rows = []
    for i, report in enumerate(reports):
        file_name = escape(Path(report.get("file_analyzed", "")).name)
        subject = escape(report.get("headers", {}).get("subject", "") or "—")
        sender = escape(report.get("headers", {}).get("from", "") or "—")
        sender_domain = escape(report.get("sender_domain", "") or "—")
        verdict = escape(report.get("assessment", {}).get("verdict", "UNKNOWN"))
        score = report.get("assessment", {}).get("score", 0)
        url_count = len(report.get("urls", []))
        attachment_count = len(report.get("attachments", []))
        keyword_hits = report.get("keyword_hits", [])
        reasons = report.get("assessment", {}).get("reasons", [])
        vclass = verdict_class(verdict)

        reasons_html = (
            "<ul class='reasons-list'>" +
            "".join(f"<li>{escape(r)}</li>" for r in reasons) +
            "</ul>"
        ) if reasons else '<span class="none-label">—</span>'

        rows.append(f"""
        <tr class="row-{vclass}" style="--delay:{i * 0.05}s">
            <td><span class="file-name">&#x1F4C4; {file_name}</span></td>
            <td class="subject-cell">{subject}</td>
            <td class="sender-cell">
                <span class="sender-name">{sender}</span>
                <span class="domain-pill">{sender_domain}</span>
            </td>
            <td><span class="verdict-badge {vclass}">{verdict}</span></td>
            <td>{score_bar(score)}</td>
            <td><span class="count-chip {'warn' if url_count > 0 else ''}">{url_count}</span></td>
            <td><span class="count-chip {'warn' if attachment_count > 0 else ''}">{attachment_count}</span></td>
            <td>{tag_list(keyword_hits, 'kw-tag')}</td>
            <td>{reasons_html}</td>
        </tr>""")

    total = len(reports)
    high_count = sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "HIGH")
    medium_count = sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "MEDIUM")
    low_count = sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "LOW")
    threat_pct = round((high_count / total * 100) if total else 0)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Analyzer</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0d0f14;
            --surface: #13161e;
            --surface2: #1a1e2a;
            --border: #252836;
            --text: #e2e8f0;
            --muted: #64748b;
            --accent: #6ee7f7;
            --high: #ff4d4d;
            --high-bg: rgba(255,77,77,0.10);
            --medium: #ffb300;
            --medium-bg: rgba(255,179,0,0.10);
            --low: #00e676;
            --low-bg: rgba(0,230,118,0.08);
            --mono: 'Space Mono', monospace;
            --sans: 'DM Sans', sans-serif;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: var(--sans);
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 0;
        }}

        /* ── HEADER ─────────────────────────────── */
        .header {{
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 28px 40px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .shield-icon {{
            width: 48px; height: 48px;
            background: linear-gradient(135deg, #6ee7f720, #6ee7f740);
            border: 1.5px solid var(--accent);
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px;
            flex-shrink: 0;
        }}
        .header h1 {{
            font-family: var(--mono);
            font-size: 20px;
            font-weight: 700;
            letter-spacing: -0.3px;
            color: var(--text);
        }}
        .header h1 span {{ color: var(--accent); }}
        .header-sub {{
            font-size: 13px;
            color: var(--muted);
            margin-top: 3px;
            font-family: var(--mono);
        }}
        .header-ts {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--muted);
            background: var(--surface2);
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 8px;
        }}

        /* ── STAT CARDS ─────────────────────────── */
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1px;
            background: var(--border);
            border-bottom: 1px solid var(--border);
        }}
        .stat-card {{
            background: var(--surface);
            padding: 24px 28px;
            position: relative;
            overflow: hidden;
            transition: background 0.2s;
        }}
        .stat-card:hover {{ background: var(--surface2); }}
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }}
        .stat-card.total::before {{ background: var(--accent); }}
        .stat-card.high-card::before {{ background: var(--high); }}
        .stat-card.medium-card::before {{ background: var(--medium); }}
        .stat-card.low-card::before {{ background: var(--low); }}

        .stat-num {{
            font-family: var(--mono);
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
        }}
        .stat-card.total .stat-num {{ color: var(--accent); }}
        .stat-card.high-card .stat-num {{ color: var(--high); }}
        .stat-card.medium-card .stat-num {{ color: var(--medium); }}
        .stat-card.low-card .stat-num {{ color: var(--low); }}

        .stat-label {{
            font-size: 12px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 6px;
            font-weight: 500;
        }}
        .stat-bar-mini {{
            margin-top: 12px;
            height: 3px;
            background: var(--border);
            border-radius: 99px;
            overflow: hidden;
        }}
        .stat-bar-mini-fill {{
            height: 100%;
            border-radius: 99px;
            transition: width 0.8s cubic-bezier(.4,0,.2,1);
        }}

        /* ── TOOLBAR ────────────────────────────── */
        .toolbar {{
            padding: 16px 40px;
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--surface);
            border-bottom: 1px solid var(--border);
        }}
        .filter-btn {{
            font-family: var(--mono);
            font-size: 12px;
            padding: 6px 14px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--muted);
            cursor: pointer;
            transition: all 0.15s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            border-color: var(--accent);
            color: var(--accent);
            background: rgba(110,231,247,0.06);
        }}
        .filter-btn.f-high.active {{ border-color: var(--high); color: var(--high); background: var(--high-bg); }}
        .filter-btn.f-medium.active {{ border-color: var(--medium); color: var(--medium); background: var(--medium-bg); }}
        .filter-btn.f-low.active {{ border-color: var(--low); color: var(--low); background: var(--low-bg); }}
        .toolbar-sep {{ flex: 1; }}
        .search-box {{
            font-family: var(--mono);
            font-size: 12px;
            padding: 7px 14px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--surface2);
            color: var(--text);
            width: 220px;
            outline: none;
            transition: border-color 0.15s;
        }}
        .search-box:focus {{ border-color: var(--accent); }}
        .search-box::placeholder {{ color: var(--muted); }}

        /* ── TABLE ──────────────────────────────── */
        .table-wrap {{
            padding: 24px 40px 40px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 13.5px;
        }}
        thead tr {{
            background: var(--surface2);
        }}
        th {{
            font-family: var(--mono);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--muted);
            padding: 12px 16px;
            text-align: left;
            white-space: nowrap;
            font-weight: 400;
            border-bottom: 1px solid var(--border);
        }}
        th:first-child {{ border-radius: 8px 0 0 0; }}
        th:last-child {{ border-radius: 0 8px 0 0; }}
        tbody tr {{
            border-bottom: 1px solid var(--border);
            animation: rowIn 0.35s ease both;
            animation-delay: var(--delay, 0s);
            transition: background 0.15s;
        }}
        @keyframes rowIn {{
            from {{ opacity: 0; transform: translateY(6px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
        tbody tr:hover {{ background: var(--surface2); }}
        tbody tr.row-high {{ border-left: 3px solid var(--high); }}
        tbody tr.row-medium {{ border-left: 3px solid var(--medium); }}
        tbody tr.row-low {{ border-left: 3px solid transparent; }}
        td {{
            padding: 14px 16px;
            vertical-align: top;
            border-bottom: 1px solid var(--border);
            color: var(--text);
        }}

        /* ── CELL COMPONENTS ────────────────────── */
        .file-name {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--accent);
            white-space: nowrap;
        }}
        .subject-cell {{ max-width: 180px; font-weight: 500; }}
        .sender-cell {{ max-width: 200px; }}
        .sender-name {{
            display: block;
            font-size: 13px;
            color: var(--text);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .domain-pill {{
            display: inline-block;
            margin-top: 4px;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            background: var(--surface2);
            border: 1px solid var(--border);
            padding: 2px 8px;
            border-radius: 4px;
        }}

        /* Verdict badge */
        .verdict-badge {{
            font-family: var(--mono);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.5px;
            padding: 4px 12px;
            border-radius: 4px;
            display: inline-block;
            white-space: nowrap;
        }}
        .verdict-badge.high {{
            background: var(--high-bg);
            color: var(--high);
            border: 1px solid rgba(255,77,77,0.3);
        }}
        .verdict-badge.medium {{
            background: var(--medium-bg);
            color: var(--medium);
            border: 1px solid rgba(255,179,0,0.3);
        }}
        .verdict-badge.low {{
            background: var(--low-bg);
            color: var(--low);
            border: 1px solid rgba(0,230,118,0.25);
        }}

        /* Score bar */
        .score-wrap {{
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 100px;
        }}
        .score-num {{
            font-family: var(--mono);
            font-size: 14px;
            font-weight: 700;
            min-width: 28px;
        }}
        .score-bar-bg {{
            flex: 1;
            height: 5px;
            background: var(--border);
            border-radius: 99px;
            overflow: hidden;
        }}
        .score-bar-fill {{
            height: 100%;
            border-radius: 99px;
            transition: width 0.8s cubic-bezier(.4,0,.2,1);
        }}

        /* Count chip */
        .count-chip {{
            font-family: var(--mono);
            font-size: 13px;
            font-weight: 700;
            color: var(--muted);
            display: inline-block;
            min-width: 24px;
            text-align: center;
        }}
        .count-chip.warn {{ color: var(--medium); }}

        /* Keyword tags */
        .kw-tag {{
            display: inline-block;
            font-family: var(--mono);
            font-size: 11px;
            background: rgba(110,231,247,0.08);
            color: var(--accent);
            border: 1px solid rgba(110,231,247,0.2);
            padding: 2px 7px;
            border-radius: 4px;
            margin: 2px 2px 2px 0;
        }}
        .none-label {{ color: var(--muted); font-size: 13px; }}

        /* Reasons list */
        .reasons-list {{
            list-style: none;
            padding: 0;
            margin: 0;
            max-width: 260px;
        }}
        .reasons-list li {{
            font-size: 12.5px;
            color: var(--muted);
            padding: 3px 0;
            padding-left: 14px;
            position: relative;
            line-height: 1.45;
        }}
        .reasons-list li::before {{
            content: '›';
            position: absolute;
            left: 0;
            color: var(--accent);
            font-weight: bold;
        }}

        /* ── FOOTER ─────────────────────────────── */
        .footer {{
            padding: 20px 40px;
            border-top: 1px solid var(--border);
            font-family: var(--mono);
            font-size: 11px;
            color: var(--muted);
            display: flex;
            justify-content: space-between;
        }}

        /* ── EMPTY STATE ────────────────────────── */
        .empty-row td {{
            text-align: center;
            color: var(--muted);
            font-family: var(--mono);
            font-size: 13px;
            padding: 40px;
        }}
    </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
    <div class="header-left">
        <div class="shield-icon">🛡️</div>
        <div>
            <h1>Phishing <span>Analyzer</span></h1>
            <div class="header-sub">Batch .eml analysis report</div>
        </div>
    </div>
    <div class="header-ts" id="ts"></div>
</div>

<!-- STATS -->
<div class="stats-bar">
    <div class="stat-card total">
        <div class="stat-num">{total}</div>
        <div class="stat-label">Total Emails</div>
        <div class="stat-bar-mini">
            <div class="stat-bar-mini-fill" style="width:100%;background:var(--accent);"></div>
        </div>
    </div>
    <div class="stat-card high-card">
        <div class="stat-num">{high_count}</div>
        <div class="stat-label">High Risk</div>
        <div class="stat-bar-mini">
            <div class="stat-bar-mini-fill" style="width:{round(high_count/total*100) if total else 0}%;background:var(--high);"></div>
        </div>
    </div>
    <div class="stat-card medium-card">
        <div class="stat-num">{medium_count}</div>
        <div class="stat-label">Medium Risk</div>
        <div class="stat-bar-mini">
            <div class="stat-bar-mini-fill" style="width:{round(medium_count/total*100) if total else 0}%;background:var(--medium);"></div>
        </div>
    </div>
    <div class="stat-card low-card">
        <div class="stat-num">{low_count}</div>
        <div class="stat-label">Low Risk</div>
        <div class="stat-bar-mini">
            <div class="stat-bar-mini-fill" style="width:{round(low_count/total*100) if total else 0}%;background:var(--low);"></div>
        </div>
    </div>
    <div class="stat-card total" style="border-left:1px solid var(--border);">
        <div class="stat-num" style="font-size:28px;">{threat_pct}%</div>
        <div class="stat-label">Threat Rate</div>
        <div class="stat-bar-mini">
            <div class="stat-bar-mini-fill" style="width:{threat_pct}%;background:{'var(--high)' if threat_pct>=70 else 'var(--medium)' if threat_pct>=30 else 'var(--low)'};"></div>
        </div>
    </div>
</div>

<!-- TOOLBAR -->
<div class="toolbar">
    <button class="filter-btn active" onclick="filterRows('ALL', this)">All</button>
    <button class="filter-btn f-high" onclick="filterRows('HIGH', this)">🔴 High</button>
    <button class="filter-btn f-medium" onclick="filterRows('MEDIUM', this)">🟡 Medium</button>
    <button class="filter-btn f-low" onclick="filterRows('LOW', this)">🟢 Low</button>
    <div class="toolbar-sep"></div>
    <input class="search-box" type="text" placeholder="Search emails…" oninput="searchRows(this.value)" />
</div>

<!-- TABLE -->
<div class="table-wrap">
    <table id="main-table">
        <thead>
            <tr>
                <th>File</th>
                <th>Subject</th>
                <th>From / Domain</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>URLs</th>
                <th>Attach.</th>
                <th>Keywords</th>
                <th>Reasons</th>
            </tr>
        </thead>
        <tbody id="table-body">
            {''.join(rows) if rows else '<tr class="empty-row"><td colspan="9">No emails analyzed yet.</td></tr>'}
        </tbody>
    </table>
</div>

<!-- FOOTER -->
<div class="footer">
    <span>Phishing Email Analyzer &mdash; Auto-generated report</span>
    <span id="count-label">{total} email{'s' if total != 1 else ''} analyzed</span>
</div>

<script>
    // Timestamp
    document.getElementById('ts').textContent = new Date().toLocaleString();

    let activeFilter = 'ALL';
    let activeSearch = '';

    function filterRows(verdict, btn) {{
        activeFilter = verdict;
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        applyFilters();
    }}

    function searchRows(val) {{
        activeSearch = val.toLowerCase();
        applyFilters();
    }}

    function applyFilters() {{
        const rows = document.querySelectorAll('#table-body tr');
        let visible = 0;
        rows.forEach(row => {{
            if (row.classList.contains('empty-row')) return;
            const vMatch = activeFilter === 'ALL' || row.classList.contains('row-' + activeFilter.toLowerCase());
            const sMatch = !activeSearch || row.textContent.toLowerCase().includes(activeSearch);
            row.style.display = (vMatch && sMatch) ? '' : 'none';
            if (vMatch && sMatch) visible++;
        }});
        document.getElementById('count-label').textContent = visible + ' email' + (visible !== 1 ? 's' : '') + ' shown';
    }}
</script>
</body>
</html>
"""

    output_path.write_text(html_content, encoding="utf-8")
