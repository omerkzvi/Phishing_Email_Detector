import pytest
from app.heuristics import PhishingHeuristics
from app.parser import  extract_hrefs
from ml.ml_classifier import ml_instance


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

def test_keyword_score_cap(h):
    text = "urgent verify password bank account security suspended immediate action"
    res = h.keyword_score(text)
    assert res["score"] == 30
    assert "urgent" in res["found"]

def test_keyword_score_empty(h):
    assert h.keyword_score("")["score"] == 0
    assert h.keyword_score(None)["score"] == 0

def test_unusual_sender_score(h):
    assert h.unusual_sender_score("secure-paypal-login.com")["score"] == 20
    assert h.unusual_sender_score("paypal.com")["score"] == 0

def test_malformed_url_parsing(h):
    broken_urls = ["!!!://broken", "http://", "None", 123]
    res = h.link_score(broken_urls)
    assert isinstance(res["score"], int)

def test_extract_hrefs_html():
    html = '<a href="https://legit.com">Click</a> <a href="www.evil.com">Phish</a>'
    links = extract_hrefs(html)
    assert "https://legit.com" in links
    assert "http://www.evil.com" in links

def test_empty_and_none_inputs(h):
    assert h.keyword_score(None)["score"] == 0
    assert h.link_score([])["score"] == 0
    assert h.url_shortener_score(None)["score"] == 0

def test_ml_prediction_format():
    result = ml_instance.predict("Please click here to update your billing information")
    assert "status" in result
    if result["status"] == "SUCCESS":
        assert "ml_score" in result
        assert 0 <= result["ml_score"] <= 100

def test_very_long_body_ml(h):
    long_text = "Free money! " * 1000
    result = ml_instance.predict(long_text)
    assert "status" in result