from pathlib import Path
from email import policy
from email.parser import BytesParser
import re
from urllib.parse import urlparse

def load_email(file_path: str):
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
    }
def extract_body(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition.lower():
                continue

            if content_type == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass

        return "\n".join(parts)
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
        
def extract_urls(text):
    url_regex = r"https?://[^\s]+"
    found_urls = re.findall(url_regex, text)

    results = []
    for url in found_urls:
        parsed = urlparse(url)
        results.append({
            "url": url,
            "domain": parsed.netloc
        })
    return results