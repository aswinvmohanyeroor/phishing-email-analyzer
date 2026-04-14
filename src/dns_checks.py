import dns.resolver


def resolve_txt(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        results = []
        for rdata in answers:
            text = "".join(
                part.decode() if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            results.append(text)
        return results
    except Exception:
        return []


def resolve_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        return []


def get_spf_record(domain):
    txt_records = resolve_txt(domain)
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def get_dmarc_record(domain):
    txt_records = resolve_txt("_dmarc." + domain)
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None