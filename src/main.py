from parser import load_email, get_basic_headers, extract_body, extract_urls
from indicators import check_domain_mismatch, suspicious_keywords, score_email
from dns_checks import get_spf_record, get_dmarc_record
from email.utils import parseaddr

def get_sender_domain(from_header):
    _, addr = parseaddr(from_header)
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return ""

file_path = "samples/sample1.eml"

msg = load_email(file_path)
headers = get_basic_headers(msg)
body = extract_body(msg)
urls = extract_urls(body)

mismatch = check_domain_mismatch(
    headers["from"],
    headers["reply_to"],
    headers["return_path"]
)

keywords = suspicious_keywords(body)
result = score_email(mismatch, urls, keywords)

sender_domain = get_sender_domain(headers["from"])
spf_record = get_spf_record(sender_domain) if sender_domain else None
dmarc_record = get_dmarc_record(sender_domain) if sender_domain else None

print("========== PHISHING EMAIL ANALYZER ==========\n")

print("From:", headers["from"])
print("To:", headers["to"])
print("Subject:", headers["subject"])
print("Date:", headers["date"])
print("Reply-To:", headers["reply_to"])
print("Return-Path:", headers["return_path"])

print("\n---------- BODY ----------")
print(body)

print("\n---------- URLS FOUND ----------")
for item in urls:
    print("-", item["url"], "| Domain:", item["domain"])

print("\n---------- DOMAIN CHECK ----------")
print("From domain:", mismatch["from_domain"])
print("Reply-To domain:", mismatch["reply_domain"])
print("Return-Path domain:", mismatch["return_domain"])
print("Reply-To mismatch:", mismatch["reply_to_mismatch"])
print("Return-Path mismatch:", mismatch["return_path_mismatch"])

print("\n---------- SUSPICIOUS WORDS ----------")
for word in keywords:
    print("-", word)

print("\n---------- DNS CHECKS ----------")
print("Sender domain:", sender_domain)
print("SPF record:", spf_record)
print("DMARC record:", dmarc_record)

print("\n---------- FINAL RESULT ----------")
print("Risk Score:", result["score"])
print("Verdict:", result["verdict"])
print("Reasons:")
for reason in result["reasons"]:
    print("-", reason)