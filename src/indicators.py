from email.utils import parseaddr
from urllib.parse import urlparse
import ipaddress
import re


RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1",
    ".zip", ".rar", ".iso", ".html", ".hta"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "cutt.ly", "ow.ly", "rb.gy", "shorturl.at"
}


def extract_email_address(header_value):
    _, addr = parseaddr(header_value or "")
    return addr.lower()


def extract_domain(email_address):
    if "@" in email_address:
        return email_address.split("@", 1)[1].lower()
    return ""


def get_authentication_results(msg):
    auth_headers = msg.get_all("Authentication-Results", [])
    joined = "\n".join(str(h) for h in auth_headers).lower()

    return {
        "spf": extract_result(joined, "spf"),
        "dkim": extract_result(joined, "dkim"),
        "dmarc": extract_result(joined, "dmarc"),
        "raw": auth_headers
    }


def extract_result(text, key):
    match = re.search(rf"{key}=(pass|fail|softfail|neutral|none|temperror|permerror)", text)
    return match.group(1) if match else "unknown"


def check_domain_mismatch(from_header, reply_to, return_path):
    from_email = extract_email_address(from_header)
    reply_email = extract_email_address(reply_to)
    return_email = extract_email_address(return_path)

    from_domain = extract_domain(from_email)
    reply_domain = extract_domain(reply_email)
    return_domain = extract_domain(return_email)

    return {
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "reply_to_mismatch": bool(reply_domain and from_domain and reply_domain != from_domain),
        "return_path_mismatch": bool(return_domain and from_domain and return_domain != from_domain)
    }


def suspicious_keywords(text, subject=""):
    words = [
        "urgent", "verify", "password", "suspended", "login",
        "immediately", "click here", "payment", "invoice",
        "confirm", "reset", "security alert", "account locked"
    ]

    combined = f"{subject}\n{text}".lower()
    found = []

    for word in words:
        if word in combined:
            found.append(word)

    return found


def check_attachment_risk(attachments):
    risky = []
    double_extension = []

    for item in attachments:
        filename = (item.get("filename") or "").lower()
        ext = item.get("extension", "")

        if ext in RISKY_EXTENSIONS:
            risky.append(filename)

        parts = filename.split(".")
        if len(parts) >= 3:
            double_extension.append(filename)

    return {
        "risky_attachments": risky,
        "double_extension_files": double_extension
    }


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def check_url_signals(urls, sender_domain):
    signals = []

    for item in urls:
        url = item["url"]
        domain = item["domain"]
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        current = {
            "url": url,
            "domain": domain,
            "domain_mismatch_with_sender": False,
            "uses_ip_address": False,
            "uses_shortener": False,
            "contains_punycode": False
        }

        if sender_domain and hostname:
            if hostname != sender_domain and not hostname.endswith("." + sender_domain):
                current["domain_mismatch_with_sender"] = True

        if hostname and is_ip_address(hostname):
            current["uses_ip_address"] = True

        if hostname in SHORTENER_DOMAINS:
            current["uses_shortener"] = True

        if "xn--" in hostname:
            current["contains_punycode"] = True

        signals.append(current)

    return signals


def check_header_signals(headers):
    issues = []

    if not headers.get("message_id"):
        issues.append("Missing Message-ID header")

    if not headers.get("date"):
        issues.append("Missing Date header")

    return issues


def score_email(auth, mismatch, urls, keyword_hits, attachment_risk, url_signals, header_issues, hidden_link_mismatches, vt_hits, has_html):
    score = 0
    reasons = []

    if auth["spf"] in {"fail", "softfail", "permerror"}:
        score += 15
        reasons.append(f"SPF suspicious: {auth['spf']}")

    if auth["dkim"] == "fail":
        score += 15
        reasons.append("DKIM failed")

    if auth["dmarc"] == "fail":
        score += 20
        reasons.append("DMARC failed")

    if mismatch["reply_to_mismatch"]:
        score += 25
        reasons.append("Reply-To domain differs from From domain")

    if mismatch["return_path_mismatch"]:
        score += 15
        reasons.append("Return-Path domain differs from From domain")

    if urls:
        score += 10
        reasons.append("Email contains URL(s)")

    if len(keyword_hits) >= 3:
        score += 15
        reasons.append("Multiple suspicious keywords found")

    if attachment_risk["risky_attachments"]:
        score += 25
        reasons.append("Risky attachment extension found")

    if vt_hits:
        score += 30
        reasons.append("VirusTotal flagged one or more attachment hashes")

    if attachment_risk["double_extension_files"]:
        score += 15
        reasons.append("Double-extension attachment found")

    for signal in url_signals:
        if signal["domain_mismatch_with_sender"]:
            score += 10
            reasons.append("URL domain differs from sender domain")
            break

    for signal in url_signals:
        if signal["uses_ip_address"]:
            score += 20
            reasons.append("URL uses IP address instead of domain")
            break

    for signal in url_signals:
        if signal["uses_shortener"]:
            score += 10
            reasons.append("URL shortener used")
            break

    for signal in url_signals:
        if signal["contains_punycode"]:
            score += 15
            reasons.append("URL contains punycode")
            break

    if header_issues:
        score += 10
        reasons.append("Some expected headers are missing")

    if hidden_link_mismatches:
        score += 20
        reasons.append("Visible link text differs from actual destination")

    if has_html and not urls:
        score += 5
        reasons.append("HTML email with limited visible context")

    if score >= 70:
        verdict = "HIGH"
    elif score >= 35:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
def extract_visible_domain(text):
    value = (text or "").strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    if "." in value and " " not in value:
        return value
    return ""
def check_hidden_link_text_mismatch(html_links):
    mismatches = []

    for item in html_links:
        visible_domain = extract_visible_domain(item.get("visible_text", ""))
        actual_domain = (urlparse(item.get("href", "")).hostname or "").lower()

        if visible_domain and actual_domain:
            if visible_domain != actual_domain and not actual_domain.endswith("." + visible_domain):
                mismatches.append({
                    "visible_text": item.get("visible_text", ""),
                    "visible_domain": visible_domain,
                    "href": item.get("href", ""),
                    "actual_domain": actual_domain
                })

    return mismatches
def check_virustotal_hits(attachments):
    hits = []

    for item in attachments:
        vt = item.get("virustotal", {})
        if vt.get("status") == "found":
            if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
                hits.append({
                    "filename": item.get("filename", ""),
                    "sha256": item.get("sha256", ""),
                    "malicious": vt.get("malicious", 0),
                    "suspicious": vt.get("suspicious", 0)
                })

    return hits