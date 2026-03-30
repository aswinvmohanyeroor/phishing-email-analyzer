from parser import load_email, get_basic_headers, extract_body, extract_urls
from indicators import check_domain_mismatch, suspicious_keywords

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

print("HEADERS:")
print(headers)

print("\nBODY:")
print(body)

print("\nURLS:")
print(urls)

print("\nDOMAIN CHECKS:")
print(mismatch)

print("\nSUSPICIOUS KEYWORDS:")
print(keywords)