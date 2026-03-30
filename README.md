# Phishing Email Analyzer

A beginner cybersecurity project in Python that analyzes `.eml` files for common phishing indicators.

## Features
- Reads email headers
- Extracts body text
- Finds URLs
- Checks Reply-To and Return-Path mismatch
- Searches for suspicious keywords
- Looks up SPF and DMARC DNS records
- Gives a simple risk score

## How to run
```bash
pip install -r requirements.txt
python src/main.py