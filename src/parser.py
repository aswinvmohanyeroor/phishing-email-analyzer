from pathlib import Path
from email import policy
from email.parser import BytesParser
import re
import hashlib
import html as html_lib
from urllib.parse import urlparse
ANCHOR_REGEX = r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>'

URL_REGEX = r"https?://[^\s\"'<>]+"
HREF_REGEX = r'href=["\'](https?://[^"\']+)["\']'


def load_email(file_path):
    path = Path(file_path)
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def get_basic_headers(msg):
    return {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "content_type": str(msg.get_content_type()),
    }


def strip_html_tags(html_text):
    if not html_text:
        return ""

    cleaned = re.sub(r"(?is)<script.*?>.*?</script>", "", html_text)
    cleaned = re.sub(r"(?is)<style.*?>.*?</style>", "", cleaned)
    cleaned = re.sub(r"(?s)<.*?>", " ", cleaned)
    cleaned = html_lib.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def extract_bodies(msg):
    text_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition.lower():
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain" and isinstance(content, str):
                text_parts.append(content)
            elif content_type == "text/html" and isinstance(content, str):
                html_parts.append(content)
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""

        if msg.get_content_type() == "text/plain":
            text_parts.append(content)
        elif msg.get_content_type() == "text/html":
            html_parts.append(content)

    text_body = "\n".join(text_parts).strip()
    html_body = "\n".join(html_parts).strip()

    if not text_body and html_body:
        text_body = strip_html_tags(html_body)

    return {
        "text": text_body,
        "html": html_body
    }


def extract_urls(text, html):
    urls = []

    for match in re.findall(URL_REGEX, text or ""):
        urls.append(match)

    for match in re.findall(HREF_REGEX, html or "", flags=re.IGNORECASE):
        urls.append(match)

    seen = set()
    results = []

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = (parsed.netloc or "").lower()
            if url not in seen:
                seen.add(url)
                results.append({
                    "url": url,
                    "domain": domain
                })
        except Exception:
            continue

    return results


def extract_attachments(msg):
    attachments = []

    for part in msg.iter_attachments():
        filename = part.get_filename() or "unknown"
        content_type = part.get_content_type()

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        sha256 = hashlib.sha256(payload).hexdigest()
        size = len(payload)

        ext = ""
        if "." in filename:
            ext = "." + filename.lower().split(".")[-1]

        attachments.append({
            "filename": filename,
            "extension": ext,
            "content_type": content_type,
            "size_bytes": size,
            "sha256": sha256
        })

    return attachments
def extract_html_links(html):
    results = []

    for href, raw_text in re.findall(ANCHOR_REGEX, html or "", flags=re.IGNORECASE | re.DOTALL):
        visible_text = strip_html_tags(raw_text)
        results.append({
            "href": href,
            "visible_text": visible_text
        })

    return results