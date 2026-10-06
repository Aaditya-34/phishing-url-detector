import os
import pytest
from src.ftr_ext import (extract_features, FEATURE_NAMES, registered_domain,
                         host_only_url, normalize_url)
from src.risk_analysis import analyze
from app import app
from src.predictor import MODEL_PATH


def test_feature_vector_shape_and_order():
    assert list(extract_features("https://google.com").keys()) == FEATURE_NAMES


def test_ip_and_at_detection():
    f = extract_features("http://192.168.1.5/login@evil")
    assert f["has_ip_address"] == 1 and f["has_at_symbol"] == 1 and f["uses_https"] == 0


def test_subdomain_and_registered_domain():
    u = "https://login.secure-paypal.com.evil.co.uk/a"
    assert extract_features(u)["num_subdomains"] == 3
    assert registered_domain(u) == "evil.co.uk"


def test_missing_scheme_and_garbage_do_not_crash():
    extract_features("example.com/path")
    extract_features("http://[bad")
    extract_features("")


def test_risk_levels():
    assert analyze("https://example.com")["level"] == "Low Risk"
    assert analyze("http://192.168.0.1/secure-login-verify@x")["level"] == "High Risk"


def test_host_only_url_scheme_and_path_stripping():
    assert host_only_url("http://example.com/some/long/path/index.html?query=val#ref") == "https://example.com"
    assert host_only_url("ftp://sub.domain.org:8080/nested/dir/") == "https://sub.domain.org"
    assert host_only_url("https://my-bank.com/") == "https://my-bank.com"


def test_host_only_url_ip_hosts():
    assert host_only_url("http://192.168.1.1:8080/login") == "https://192.168.1.1"
    assert host_only_url("http://10.0.0.1/") == "https://10.0.0.1"


def test_host_only_url_junk_input():
    # Must not raise exceptions on malformed / empty / invalid input
    assert host_only_url("") == "https://"
    assert host_only_url("http://[bad") == "https://"
    assert host_only_url("not a valid url").startswith("https://")


def test_whitelist_is_exact_not_substring():
    pytest.importorskip("joblib")
    from src.predictor import Detector
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    d = Detector()
    # Whitelisted legitimate domain
    assert d.predict("https://www.google.com")["source"].startswith("trusted")
    # Exact registered domain match only: attacker attempts to bypass whitelist
    evil_domain = "https://google.com.evil.tk/login"
    assert not d.predict(evil_domain)["source"].startswith("trusted")
    assert registered_domain(evil_domain) != "google.com"

    evil_domain_sub = "https://login.paypal.com.attacker.com"
    assert not d.predict(evil_domain_sub)["source"].startswith("trusted")
    assert registered_domain(evil_domain_sub) == "attacker.com"


# --- Flask Endpoint Integration Tests ---

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_flask_predict_valid_url(client):
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    res = client.post("/predict", data={"url": "https://google.com"})
    assert res.status_code == 200
    assert b"Prediction Result" in res.data
    assert b"Legitimate Website" in res.data


def test_flask_predict_empty_input_returns_400(client):
    res = client.post("/predict", data={"url": ""})
    assert res.status_code == 400
    assert b"Please enter a valid URL" in res.data


def test_flask_predict_over_2048_chars_returns_400(client):
    long_url = "https://example.com/" + ("a" * 2050)
    res = client.post("/predict", data={"url": long_url})
    assert res.status_code == 400
    assert b"max 2048 chars" in res.data


def test_flask_predict_garbage_input_no_500(client):
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    res = client.post("/predict", data={"url": "http://[invalid-ipv6:99999"})
    assert res.status_code != 500


def test_flask_api_predict_valid_and_keys(client):
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    res = client.post("/api/predict", json={"url": "https://google.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, dict)
    expected_keys = ["url", "verdict", "label", "phishing", "confidence", "source", "score", "level", "reasons"]
    for k in expected_keys:
        assert k in data, f"Missing key '{k}' in api response"
    assert data["phishing"] is False
    assert data["verdict"] == "Legitimate Website"
    assert data["source"] == "trusted-domain whitelist"


def test_three_state_verdict(client):
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    # 1. Whitelist path -> Legitimate Website
    res_legit = client.post("/api/predict", json={"url": "https://google.com"}).get_json()
    assert res_legit["verdict"] == "Legitimate Website"
    assert res_legit["source"] == "trusted-domain whitelist"

    # 2. ML Phishing path -> Phishing Website
    res_ml_phish = client.post("/api/predict", json={"url": "http://192.168.1.1/login"}).get_json()
    assert res_ml_phish["phishing"] is True
    assert res_ml_phish["verdict"] == "Phishing Website"

    # 3. ML Legitimate but Rule Score >= 50 -> Suspicious Website
    res_susp = client.post("/api/predict", json={"url": "http://secure-paypal-login.xyz/verify"}).get_json()
    assert res_susp["phishing"] is False
    assert res_susp["score"] >= 50
    assert res_susp["verdict"] == "Suspicious Website"


def test_flask_api_predict_empty_input_returns_400(client):
    res1 = client.post("/api/predict", json={"url": ""})
    assert res1.status_code == 400
    res2 = client.post("/api/predict", json={})
    assert res2.status_code == 400
    res3 = client.post("/api/predict", data="not json", content_type="application/json")
    assert res3.status_code == 400


def test_flask_api_predict_over_2048_chars_returns_400(client):
    long_url = "https://example.com/" + ("a" * 2050)
    res = client.post("/api/predict", json={"url": long_url})
    assert res.status_code == 400
    assert "max 2048 chars" in res.get_json()["error"]


def test_flask_api_predict_garbage_input_no_500(client):
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    res = client.post("/api/predict", json={"url": "http://[invalid-ipv6"})
    assert res.status_code != 500
