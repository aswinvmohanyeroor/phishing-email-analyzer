import unittest

from src.indicators import check_hidden_link_text_mismatch


class TestHiddenLinks(unittest.TestCase):
    def test_hidden_link_mismatch_detected(self):
        html_links = [
            {
                "visible_text": "https://microsoft.com/reset",
                "href": "http://evil-login-example.com/reset"
            }
        ]

        result = check_hidden_link_text_mismatch(html_links)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["visible_domain"], "microsoft.com")


if __name__ == "__main__":
    unittest.main()