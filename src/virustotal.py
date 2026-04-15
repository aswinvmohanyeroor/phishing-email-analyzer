import os
import requests


VT_BASE_URL = "https://www.virustotal.com/api/v3/files"


def get_vt_api_key():
    return os.getenv("VT_API_KEY", "").strip()


def lookup_file_hash(sha256, api_key, timeout=15):
    if not api_key:
        return {"status": "disabled", "sha256": sha256}

    url = f"{VT_BASE_URL}/{sha256}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)

        if response.status_code == 404:
            return {"status": "not_found", "sha256": sha256}

        response.raise_for_status()

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "found",
            "sha256": sha256,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except Exception as e:
        return {
            "status": "error",
            "sha256": sha256,
            "error": str(e)
        }


def enrich_attachments_with_virustotal(attachments, api_key):
    enriched = []

    for item in attachments:
        updated = dict(item)
        updated["virustotal"] = lookup_file_hash(updated["sha256"], api_key)
        enriched.append(updated)

    return enriched