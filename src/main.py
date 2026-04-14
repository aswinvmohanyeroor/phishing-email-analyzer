import argparse
from pathlib import Path
from email.utils import parseaddr
from parser import load_email, get_basic_headers, extract_bodies, extract_urls, extract_attachments
from reporter import save_json_report, save_text_report
from indicators import (
    get_authentication_results,
    check_domain_mismatch,
    suspicious_keywords,
    check_attachment_risk,
    check_url_signals,
    check_header_signals,
    score_email
)
from dns_checks import get_spf_record, get_dmarc_record, resolve_mx
from reporter import save_json_report


def get_sender_domain(from_header):
    _, addr = parseaddr(from_header or "")
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return ""


def analyze_email(file_path, output_dir):
    msg = load_email(file_path)
    headers = get_basic_headers(msg)
    bodies = extract_bodies(msg)
    urls = extract_urls(bodies["text"], bodies["html"])
    attachments = extract_attachments(msg)

    auth = get_authentication_results(msg)
    mismatch = check_domain_mismatch(
        headers["from"],
        headers["reply_to"],
        headers["return_path"]
    )

    keyword_hits = suspicious_keywords(bodies["text"], headers["subject"])
    attachment_risk = check_attachment_risk(attachments)

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
        "header_issues": header_issues,
        "keyword_hits": keyword_hits,
        "domain_checks": mismatch,
        "assessment": scoring
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


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Analyzer")
    parser.add_argument("files", nargs="+", help="One or more .eml files to analyze")
    parser.add_argument("-o", "--output", default="output", help="Output folder for JSON reports")
    args = parser.parse_args()

    for file_path in args.files:
        try:
            analyze_email(file_path, args.output)
        except Exception as e:
            print("\n========================================")
            print("File:", file_path)
            print("Error:", str(e))


if __name__ == "__main__":
    main()