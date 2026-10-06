"""Robustness testing against simple lexical perturbations.
Usage: python scripts/robustness_test.py
Saves results to reports/robustness.json

Note: This evaluates robustness to simple lexical evasion only, not a real adversary.
"""
import json
import os
import sys
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ftr_ext import feature_vector, host_only_url, registered_domain, normalize_url
from src.predictor import Detector

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def perturb_add_www(url: str) -> str:
    """Add a 'www' subdomain (e.g. login.evil.com -> www.login.evil.com)."""
    p = urlparse(normalize_url(url))
    host = p.netloc or p.path
    if host.startswith("www."):
        new_host = "www2." + host[4:]
    else:
        new_host = "www." + host
    return f"{p.scheme or 'https'}://{new_host}"


def perturb_insert_hyphen(url: str) -> str:
    """Insert one hyphen into the domain name."""
    p = urlparse(normalize_url(url))
    host = p.netloc or p.path
    ext = _EXTRACT(host)
    dom = ext.domain
    if len(dom) > 1:
        mid = len(dom) // 2
        new_dom = dom[:mid] + "-" + dom[mid:]
    else:
        new_dom = dom + "-x"
    sub = ext.subdomain
    suf = ext.suffix or "com"
    new_host = f"{sub}.{new_dom}.{suf}" if sub else f"{new_dom}.{suf}"
    return f"{p.scheme or 'https'}://{new_host}"


def perturb_swap_tld_to_com(url: str) -> str:
    """Swap the TLD to .com."""
    p = urlparse(normalize_url(url))
    host = p.netloc or p.path
    ext = _EXTRACT(host)
    sub = ext.subdomain
    dom = ext.domain or "domain"
    new_host = f"{sub}.{dom}.com" if sub else f"{dom}.com"
    return f"{p.scheme or 'https'}://{new_host}"


def perturb_append_numeric(url: str) -> str:
    """Append a short numeric label (e.g. -01) to the domain name."""
    p = urlparse(normalize_url(url))
    host = p.netloc or p.path
    ext = _EXTRACT(host)
    dom = (ext.domain or "site") + "-01"
    sub = ext.subdomain
    suf = ext.suffix or "com"
    new_host = f"{sub}.{dom}.{suf}" if sub else f"{dom}.{suf}"
    return f"{p.scheme or 'https'}://{new_host}"


def perturb_lengthen_subdomain(url: str) -> str:
    """Lengthen the subdomain by prepending an additional subdomain label."""
    p = urlparse(normalize_url(url))
    host = p.netloc or p.path
    ext = _EXTRACT(host)
    sub = f"portal.{ext.subdomain}" if ext.subdomain else "portal"
    dom = ext.domain or "domain"
    suf = ext.suffix or "com"
    new_host = f"{sub}.{dom}.{suf}"
    return f"{p.scheme or 'https'}://{new_host}"


def batch_predict_phishing(detector: Detector, urls: list) -> list:
    """Fast batch prediction reproducing Detector.predict decision logic."""
    class_idx = list(detector.model.classes_).index(1)
    results = [False] * len(urls)
    ml_indices = []
    ml_urls = []

    for i, u in enumerate(urls):
        norm = normalize_url(u)
        if registered_domain(norm) in detector.whitelist:
            results[i] = False
        else:
            ml_indices.append(i)
            target = host_only_url(norm) if detector.host_only else norm
            ml_urls.append(target)

    if ml_urls:
        X = np.array([feature_vector(u) for u in ml_urls])
        probas = detector.model.predict_proba(X)[:, class_idx]
        for idx, p in zip(ml_indices, probas):
            results[idx] = bool(p >= 0.5)

    return results


def main():
    print("Loading Detector and dataset...")
    detector = Detector()
    data_path = os.path.join(ROOT, "data", "dataset.csv")
    df = pd.read_csv(data_path)[["url", "label"]].dropna().drop_duplicates("url")

    # Host-only deduplication matching train.py
    if detector.host_only:
        df["url"] = df.url.map(host_only_url)
        df = df.drop_duplicates(["url", "label"])
        df = df.drop_duplicates("url", keep=False)

    groups = df.url.map(registered_domain).values
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    _, te = next(gss.split(df, df.label.values, groups))
    test_df = df.iloc[te].copy()

    phish_test = test_df[test_df.label == 1]
    # Filter to correctly detected phishing hosts
    baseline_predictions = batch_predict_phishing(detector, phish_test.url.tolist())
    correct_phish_urls = [u for u, is_phish in zip(phish_test.url, baseline_predictions) if is_phish]
    n_baseline = len(correct_phish_urls)

    print(f"Total test phishing hosts: {len(phish_test)}")
    print(f"Correctly detected baseline phishing hosts: {n_baseline}")

    perturbations = {
        "add_www_subdomain": {
            "name": "Add 'www' subdomain",
            "func": perturb_add_www,
            "description": "Prepends 'www.' to the hostname or replaces with www2.",
        },
        "insert_one_hyphen": {
            "name": "Insert one hyphen",
            "func": perturb_insert_hyphen,
            "description": "Inserts a hyphen into the registered domain body.",
        },
        "swap_tld_to_com": {
            "name": "Swap TLD to .com",
            "func": perturb_swap_tld_to_com,
            "description": "Replaces the original top-level domain with .com.",
        },
        "append_short_numeric": {
            "name": "Append short numeric label",
            "func": perturb_append_numeric,
            "description": "Appends a numeric label (-01) to the domain name.",
        },
        "lengthen_subdomain": {
            "name": "Lengthen subdomain",
            "func": perturb_lengthen_subdomain,
            "description": "Prepends an extra 'portal.' label to the subdomain structure.",
        },
    }

    results = {
        "note": "Evaluates robustness to simple lexical evasion only, not a real adversary.",
        "n_baseline_correct": n_baseline,
        "baseline_detection_rate": 1.0,
        "perturbations": {},
    }

    print("\n=== PERTURBATION ROBUSTNESS RESULTS ===")
    for key, item in perturbations.items():
        perturbed_urls = [item["func"](u) for u in correct_phish_urls]
        detected = batch_predict_phishing(detector, perturbed_urls)
        n_detected = int(sum(detected))
        det_rate = n_detected / n_baseline
        evasion_rate = 1.0 - det_rate

        results["perturbations"][key] = {
            "perturbation_name": item["name"],
            "description": item["description"],
            "detected_count": n_detected,
            "total_tested": n_baseline,
            "detection_rate": round(det_rate, 4),
            "evasion_rate": round(evasion_rate, 4),
            "detection_rate_pct": round(det_rate * 100, 2),
            "evasion_rate_pct": round(evasion_rate * 100, 2),
        }
        print(f"{item['name']:28s} -> Detected: {n_detected:4d}/{n_baseline:4d} "
              f"({det_rate*100:.2f}%) | Evasion: {evasion_rate*100:.2f}%")

    out_file = os.path.join(ROOT, "reports", "robustness.json")
    with open(out_file, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nSaved robustness report to {out_file}")


if __name__ == "__main__":
    main()
