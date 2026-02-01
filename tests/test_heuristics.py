import pytest
from app.heuristics import PhishingHeuristics

@pytest.fixture()
def h():
    return PhishingHeuristics()

def test_url_shortener_score(h):
    res = h.url_shortener_score(["https://bit.ly/abc"])
    assert res["score"] == 10

def test_punycode_score(h):
    res = h.punycode_score(["https://xn--pple-43d.com/login"])
    assert res["score"] == 10

def test_ip_url_score(h):
    res = h.ip_url_score(["http://192.168.1.10/login"])
    assert res["score"] == 10

def test_at_symbol_url_score(h):
    res = h.at_symbol_url_score(["http://example.com@evil.com/login"])
    assert res["score"] == 10

def test_many_dashes_domain_score(h):
    res = h.many_dashes_domain_score(["http://a-b-c-d-e.com/path"])
    assert res["score"] == 10

def test_suspicious_tld_score(h):
    res = h.suspicious_tld_score(["http://example.zip/login"])
    assert res["score"] == 10

def test_reply_to_mismatch_score(h):
    headers = {"Reply-To": "Someone <reply@evil.com>"}
    res = h.reply_to_mismatch_score("google.com", headers)
    assert res["score"] == 15
