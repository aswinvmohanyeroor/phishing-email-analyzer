import tempfile
import unittest
from pathlib import Path

from src.parser import load_email, get_basic_headers, extract_bodies, extract_urls


PLAIN_EMAIL = b"""From: tester@example.com
To: user@test.com
Subject: Test message
Date: Mon, 30 Mar 2026 10:00:00 +0800
Content-Type: text/plain; charset="utf-8"

Please verify your account at http://example.com/login
"""

HTML_EMAIL = b"""From: alerts@example.com
To: user@test.com
Subject: HTML message
Date: Mon, 30 Mar 2026 10:00:00 +0800
Content-Type: text/html; charset="utf-8"

<html>
  <body>
    <p>Click <a href="http://example.com/reset">here</a> now</p>
  </body>
</html>
"""


class TestParser(unittest.TestCase):
    def test_plain_email_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "plain.eml"
            file_path.write_bytes(PLAIN_EMAIL)

            msg = load_email(file_path)
            headers = get_basic_headers(msg)
            bodies = extract_bodies(msg)
            urls = extract_urls(bodies["text"], bodies["html"])

            self.assertEqual(headers["subject"], "Test message")
            self.assertIn("verify your account", bodies["text"])
            self.assertEqual(len(urls), 1)
            self.assertEqual(urls[0]["domain"], "example.com")

    def test_html_email_text_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "html.eml"
            file_path.write_bytes(HTML_EMAIL)

            msg = load_email(file_path)
            bodies = extract_bodies(msg)

            self.assertTrue(bodies["html"])
            self.assertIn("Click", bodies["text"])


if __name__ == "__main__":
    unittest.main()