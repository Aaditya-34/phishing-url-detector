"""Glue: whitelist -> features -> ML model + rule-based audit."""
import os
import joblib
from src.ftr_ext import FEATURE_NAMES, feature_vector, registered_domain, normalize_url, host_only_url
from src.risk_analysis import analyze

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "models", "model.pkl")
WHITELIST_PATH = os.path.join(ROOT, "data", "trusted_domains.txt")


def load_whitelist():
    if not os.path.exists(WHITELIST_PATH):
        return set()
    with open(WHITELIST_PATH) as fh:
        return {l.strip().lower() for l in fh if l.strip() and not l.startswith("#")}


class Detector:
    def __init__(self):
        self.whitelist = load_whitelist()
        bundle = joblib.load(MODEL_PATH)
        self.model, self.features = bundle["model"], bundle["features"]
        self.host_only = bundle.get("host_only", False)
        assert self.features == FEATURE_NAMES, "Model/feature mismatch: retrain the model"

    def predict(self, url: str) -> dict:
        url = normalize_url(url)
        audit = analyze(url)
        # exact registered-domain match only (never substring: paypal.com.evil.tk must NOT pass)
        if registered_domain(url) in self.whitelist:
            return {"url": url, "verdict": "Legitimate Website", "label": "Legitimate Website",
                    "phishing": False, "confidence": 99.99,
                    "source": "trusted-domain whitelist", **audit}
        proba = self.model.predict_proba([feature_vector(host_only_url(url) if self.host_only else url)])[0]
        p_phish = float(proba[list(self.model.classes_).index(1)])
        phishing = p_phish >= 0.5
        label = "Phishing Website" if phishing else "Legitimate Website"
        if phishing:
            verdict = "Phishing Website"
        elif audit.get("score", 0) >= 50:
            verdict = "Suspicious Website"
        else:
            verdict = "Legitimate Website"
        return {"url": url, "verdict": verdict, "label": label,
                "phishing": phishing,
                "confidence": round((p_phish if phishing else 1 - p_phish) * 100, 2),
                "source": "Random Forest model", **audit}
