import argparse
from pathlib import Path
from email.utils import parseaddr

from reporter import save_json_report, save_text_report, save_csv_summary, save_html_summary
from parser import (
    load_email,
    get_basic_headers,
    extract_bodies,
    extract_urls,
    extract_attachments,
    extract_html_links,
)
from virustotal import get_vt_api_key, enrich_attachments_with_virustotal
from indicators import (
    get_authentication_results,
    check_domain_mismatch,
    suspicious_keywords,
    check_attachment_risk,
    check_url_signals,
    check_header_signals,
    check_hidden_link_text_mismatch,
    check_virustotal_hits,
    score_email,
)
from dns_checks import get_spf_record, get_dmarc_record, resolve_mx


def get_sender_domain(from_header):
    _, addr = parseaddr(from_header or "")
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return ""


def collect_eml_files(folder_path, recursive=False):
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Folder not found: {folder_path}")

    pattern = "**/*.eml" if recursive else "*.eml"
    return [str(p) for p in sorted(folder.glob(pattern)) if p.is_file()]


def analyze_email(file_path, output_dir):
    msg = load_email(file_path)
    headers = get_basic_headers(msg)
    bodies = extract_bodies(msg)
    urls = extract_urls(bodies["text"], bodies["html"])

    attachments = extract_attachments(msg)
    vt_api_key = get_vt_api_key()
    if attachments:
        attachments = enrich_attachments_with_virustotal(attachments, vt_api_key)

    html_links = extract_html_links(bodies["html"])
    hidden_link_mismatches = check_hidden_link_text_mismatch(html_links)

    auth = get_authentication_results(msg)
    mismatch = check_domain_mismatch(
        headers["from"],
        headers["reply_to"],
        headers["return_path"]
    )

    keyword_hits = suspicious_keywords(bodies["text"], headers["subject"])
    attachment_risk = check_attachment_risk(attachments)
    vt_hits = check_virustotal_hits(attachments)

    sender_domain = get_sender_domain(headers["from"])
    url_signals = check_url_signals(urls, sender_domain)
    header_issues = check_header_signals(headers)

    spf_record = get_spf_record(sender_domain) if sender_domain else None
    dmarc_record = get_dmarc_record(sender_domain) if sender_domain else None
    mx_records = resolve_mx(sender_domain) if sender_domain else []

    scoring = score_email(
        auth=auth,
        mismatch=mismatch,
        urls=urls,
        keyword_hits=keyword_hits,
        attachment_risk=attachment_risk,
        url_signals=url_signals,
        header_issues=header_issues,
        hidden_link_mismatches=hidden_link_mismatches,
        vt_hits=vt_hits,
        has_html=bool(bodies["html"])
    )

    report = {
        "file_analyzed": str(file_path),
        "headers": headers,
        "sender_domain": sender_domain,
        "authentication": auth,
        "dns": {
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "mx_records": mx_records
        },
        "bodies": {
            "text": bodies["text"],
            "html_present": bool(bodies["html"]),
            "html_preview": bodies["html"][:500]
        },
        "urls": urls,
        "url_signals": url_signals,
        "attachments": attachments,
        "attachment_risk": attachment_risk,
        "virustotal": {
            "enabled": bool(vt_api_key),
            "hits": vt_hits
        },
        "header_issues": header_issues,
        "keyword_hits": keyword_hits,
        "domain_checks": mismatch,
        "html_links": html_links,
        "hidden_link_mismatches": hidden_link_mismatches,
        "assessment": scoring,
    }

    input_path = Path(file_path)
    json_output_file = Path(output_dir) / f"{input_path.stem}_report.json"
    txt_output_file = Path(output_dir) / f"{input_path.stem}_report.txt"

    save_json_report(report, json_output_file)
    save_text_report(report, txt_output_file)

    print("\n========================================")
    print("File:", file_path)
    print("Subject:", headers["subject"])
    print("From:", headers["from"])
    print("Verdict:", scoring["verdict"])
    print("Risk Score:", scoring["score"])
    print("Saved JSON:", json_output_file)
    print("Saved TXT:", txt_output_file)

    if scoring["reasons"]:
        print("Reasons:")
        for reason in scoring["reasons"]:
            print("-", reason)

    return report


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser.add_argument("files", nargs="*", help="One or more .eml files to analyze")
    parser.add_argument("--folder", help="Analyze all .eml files in a folder")
    parser.add_argument("--recursive", action="store_true", help="Search subfolders too")
    parser.add_argument("-o", "--output", default="output", help="Output folder for reports")
    args = parser.parse_args()

    files_to_analyze = []

    if args.folder:
        files_to_analyze.extend(collect_eml_files(args.folder, args.recursive))

    if args.files:
        files_to_analyze.extend(args.files)

    files_to_analyze = list(dict.fromkeys(files_to_analyze))

    if not files_to_analyze:
        parser.error("Provide one or more .eml files, or use --folder")

    reports = []

    for file_path in files_to_analyze:
        try:
            report = analyze_email(file_path, args.output)
            reports.append(report)
        except Exception as e:
            print("\n========================================")
            print("File:", file_path)
            print("Error:", str(e))

    print("\nCompleted analysis for", len(reports), "file(s)")

    if reports:
        summary_file = Path(args.output) / "analysis_summary.csv"
        save_csv_summary(reports, summary_file)
        print("Saved CSV summary:", summary_file)

        html_summary_file = Path(args.output) / "analysis_summary.html"
        save_html_summary(reports, html_summary_file)
        print("Saved HTML summary:", html_summary_file)

if __name__ == "__main__":
    main()