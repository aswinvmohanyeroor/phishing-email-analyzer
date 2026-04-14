import unittest

from src.indicators import check_domain_mismatch, check_attachment_risk


class TestIndicators(unittest.TestCase):
    def test_domain_mismatch_detected(self):
        result = check_domain_mismatch(
            '"Fake Bank" <support@fakebank.com>',
            'attacker@gmail.com',
            'bounce@fakebank-mail.com'
        )

        self.assertTrue(result["reply_to_mismatch"])
        self.assertTrue(result["return_path_mismatch"])

    def test_attachment_risk_detected(self):
        attachments = [
            {
                "filename": "invoice.pdf.exe",
                "extension": ".exe",
                "content_type": "application/octet-stream",
                "size_bytes": 1200,
                "sha256": "abc123"
            },
            {
                "filename": "notes.txt",
                "extension": ".txt",
                "content_type": "text/plain",
                "size_bytes": 100,
                "sha256": "def456"
            }
        ]

        result = check_attachment_risk(attachments)

        self.assertIn("invoice.pdf.exe", result["risky_attachments"])
        self.assertIn("invoice.pdf.exe", result["double_extension_files"])


if __name__ == "__main__":
    unittest.main()