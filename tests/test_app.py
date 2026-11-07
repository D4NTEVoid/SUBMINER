import unittest

import app


class DomainValidationTests(unittest.TestCase):
    def test_normalizes_domain(self):
        self.assertEqual(app.normalize_domain("Example.COM"), "example.com")

    def test_rejects_invalid_domain_input(self):
        for value in ("", "example.com/path", "-bad.example.com", "example", None, 123):
            with self.subTest(value=value):
                self.assertIsNone(app.normalize_domain(value))

    def test_accepts_only_subdomains_of_target(self):
        self.assertEqual(app.normalize_hostname("WWW.Example.com.", "example.com"), "www.example.com")
        self.assertIsNone(app.normalize_hostname("example.com", "example.com"))
        self.assertIsNone(app.normalize_hostname("notexample.com", "example.com"))
        self.assertIsNone(app.normalize_hostname("example.com.attacker.test", "example.com"))

    def test_idna_hostname(self):
        self.assertEqual(
            app.normalize_hostname("xn--bcher-kva.example.com", "example.com"),
            "xn--bcher-kva.example.com",
        )


class ParserTests(unittest.TestCase):
    def test_crtsh_parser(self):
        raw = '[{"common_name":"a.example.com","name_value":"b.example.com\\n*.c.example.com"}]'
        self.assertEqual(
            set(app.parse_crtsh(raw)),
            {"a.example.com", "b.example.com", "*.c.example.com"},
        )

    def test_urlscan_parser(self):
        raw = '{"results":[{"page":{"domain":"www.example.com"}},{"page":{"domain":"api.example.com"}}]}'
        self.assertEqual(
            set(app.parse_urlscan(raw)),
            {"www.example.com", "api.example.com"},
        )


if __name__ == "__main__":
    unittest.main()
