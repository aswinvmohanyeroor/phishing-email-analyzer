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
        verdict = (verdict or "").upper()
        if verdict == "HIGH":
            return "high"
        if verdict == "MEDIUM":
            return "medium"
        return "low"

    rows = []

    for report in reports:
        file_name = escape(Path(report.get("file_analyzed", "")).name)
        subject = escape(report.get("headers", {}).get("subject", ""))
        sender = escape(report.get("headers", {}).get("from", ""))
        sender_domain = escape(report.get("sender_domain", ""))
        verdict = escape(report.get("assessment", {}).get("verdict", "UNKNOWN"))
        score = report.get("assessment", {}).get("score", 0)
        url_count = len(report.get("urls", []))
        attachment_count = len(report.get("attachments", []))
        keyword_count = len(report.get("keyword_hits", []))
        reasons = report.get("assessment", {}).get("reasons", [])
        reasons_html = "<br>".join(escape(reason) for reason in reasons) if reasons else "None"

        rows.append(f"""
        <tr>
            <td>{file_name}</td>
            <td>{subject}</td>
            <td>{sender}</td>
            <td>{sender_domain}</td>
            <td><span class="badge {verdict_class(verdict)}">{verdict}</span></td>
            <td>{score}</td>
            <td>{url_count}</td>
            <td>{attachment_count}</td>
            <td>{keyword_count}</td>
            <td>{reasons_html}</td>
        </tr>
        """)

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Analyzer - HTML Summary</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 24px;
            background: #f7f9fc;
            color: #222;
        }}
        h1 {{
            margin-bottom: 8px;
        }}
        p {{
            color: #555;
        }}
        .summary {{
            display: flex;
            gap: 16px;
            margin: 20px 0;
            flex-wrap: wrap;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 16px;
            min-width: 180px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .card h2 {{
            margin: 0;
            font-size: 24px;
        }}
        .card span {{
            color: #666;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-radius: 10px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #f0f3f8;
        }}
        tr:hover {{
            background: #fafcff;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
        }}
        .high {{
            background: #ffd9d9;
            color: #a40000;
        }}
        .medium {{
            background: #fff0c7;
            color: #8a5a00;
        }}
        .low {{
            background: #dff5df;
            color: #176b17;
        }}
    </style>
</head>
<body>
    <h1>Phishing Email Analyzer Summary</h1>
    <p>Batch analysis dashboard for all processed .eml files.</p>

    <div class="summary">
        <div class="card">
            <h2>{len(reports)}</h2>
            <span>Total Emails</span>
        </div>
        <div class="card">
            <h2>{sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "HIGH")}</h2>
            <span>High Risk</span>
        </div>
        <div class="card">
            <h2>{sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "MEDIUM")}</h2>
            <span>Medium Risk</span>
        </div>
        <div class="card">
            <h2>{sum(1 for r in reports if r.get("assessment", {}).get("verdict") == "LOW")}</h2>
            <span>Low Risk</span>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>File</th>
                <th>Subject</th>
                <th>From</th>
                <th>Sender Domain</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>URLs</th>
                <th>Attachments</th>
                <th>Keywords</th>
                <th>Reasons</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>
"""

    output_path.write_text(html_content, encoding="utf-8")