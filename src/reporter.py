import json
from pathlib import Path


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
            lines.append(
                f"- {item.get('filename', '')} | ext={item.get('extension', '')} | size={item.get('size_bytes', 0)}"
            )
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