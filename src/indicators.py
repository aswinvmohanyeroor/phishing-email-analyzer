from email.utils import parseaddr

def extract_email_address(header_value):
    _, addr = parseaddr(header_value or "")
    return addr.lower()

def extract_domain(email_address):
    if "@" in email_address:
        return email_address.split("@", 1)[1].lower()
    return ""

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
        "reply_to_mismatch": reply_domain != "" and from_domain != "" and reply_domain != from_domain,
        "return_path_mismatch": return_domain != "" and from_domain != "" and return_domain != from_domain
    }

def suspicious_keywords(text):
    words = [
        "urgent",
        "verify",
        "password",
        "suspended",
        "login",
        "immediately",
        "click here",
        "payment",
        "invoice"
    ]

    found = []
    lower_text = text.lower()

    for word in words:
        if word in lower_text:
            found.append(word)

    return found