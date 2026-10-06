"""Rule-based security auditing (risk_analysis.py).

Produces a 0-100 heuristic risk score, a severity level and human-readable
reasons. Independent of the ML model so the two can be shown side by side.
"""
from src.ftr_ext import extract_features

# (feature test, weight, bad message, good message)
def analyze(url: str) -> dict:
    f = extract_features(url)
    score, reasons = 0, []

    def check(bad: bool, weight: int, bad_msg: str, good_msg: str):
        nonlocal score
        if bad:
            score += weight
        reasons.append({"ok": not bad, "text": bad_msg if bad else good_msg})

    check(not f["uses_https"], 15, "Does not use HTTPS", "HTTPS enabled")
    check(f["has_ip_address"], 25, "Uses an IP address instead of a domain name", "Uses a domain name")
    check(f["has_at_symbol"], 15, "Contains '@' symbol (can hide the real destination)", "No '@' symbol")
    check(f["has_punycode"], 15, "Punycode (xn--) may indicate a look-alike domain", "No punycode / look-alike encoding")
    check(f["is_shortener"], 10, "URL shortener hides the final destination", "Not a URL shortener")
    check(f["suspicious_tld"], 10, "TLD frequently abused in phishing", "TLD is not commonly abused")
    check(f["num_subdomains"] > 2, 10, f"Too many subdomains ({f['num_subdomains']})", "Normal number of subdomains")
    check(f["domain_hyphens"] >= 2, 10, "Many hyphens in the domain name", "Normal domain structure")
    check(f["url_length"] > 75, 10, f"Long URL ({f['url_length']} characters)", "URL length is normal")
    check(f["has_port"], 5, "Uses a non-standard port", "Standard port")
    check(f["suspicious_keyword_count"] >= 2, 15,
          f"Contains {f['suspicious_keyword_count']} phishing-style keywords", "No suspicious keywords")
    check(f["domain_entropy"] > 3.8, 5, "Domain looks random (high entropy)", "Domain looks natural")
    score = min(score, 100)
    level = "Low Risk" if score < 25 else "Medium Risk" if score < 50 else "High Risk"
    return {"score": score, "level": level, "reasons": reasons}
