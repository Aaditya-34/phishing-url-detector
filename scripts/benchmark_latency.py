"""Benchmark latency for feature extraction, model inference, and Detector.predict.
Usage: python scripts/benchmark_latency.py
Saves results to reports/latency.json
"""
import json
import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ftr_ext import feature_vector, registered_domain, host_only_url
from src.predictor import Detector, load_whitelist

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def calc_stats(times_ms):
    arr = np.array(times_ms)
    return {
        "mean_ms": round(float(np.mean(arr)), 4),
        "p50_ms": round(float(np.percentile(arr, 50)), 4),
        "p95_ms": round(float(np.percentile(arr, 95)), 4),
        "p99_ms": round(float(np.percentile(arr, 99)), 4),
        "min_ms": round(float(np.min(arr)), 4),
        "max_ms": round(float(np.max(arr)), 4),
    }


def main():
    print("Initializing Detector...")
    detector = Detector()
    whitelist = load_whitelist()

    data_path = os.path.join(ROOT, "data", "dataset.csv")
    df = pd.read_csv(data_path)[["url", "label"]].dropna().drop_duplicates("url")

    # Host-only deduplication matching the deployed model's evaluation protocol
    if detector.host_only:
        df["url"] = df.url.map(host_only_url)
        df = df.drop_duplicates(["url", "label"])
        df = df.drop_duplicates("url", keep=False)

    groups = df.url.map(registered_domain).values
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    _, te = next(gss.split(df, df.label.values, groups))
    test_df = df.iloc[te].copy()

    # Exclude any URLs that might match the whitelist so we benchmark the pure ML path
    test_ml_urls = [u for u in test_df.url if registered_domain(u) not in whitelist]
    if len(test_ml_urls) > 1000:
        # 1,000 held-out URLs sampled with seed 42
        sample_ml_urls = pd.Series(test_ml_urls).sample(1000, random_state=42).tolist()
    else:
        sample_ml_urls = test_ml_urls[:1000]

    print(f"Sampled {len(sample_ml_urls)} held-out URLs for ML pipeline benchmark.")

    # Warmup
    for u in sample_ml_urls[:50]:
        _ = detector.predict(u)

    # 1. Feature extraction timing
    feat_times = []
    feat_vectors = []
    for u in sample_ml_urls:
        url_input = host_only_url(u) if detector.host_only else u
        t0 = time.perf_counter()
        fv = feature_vector(url_input)
        t1 = time.perf_counter()
        feat_times.append((t1 - t0) * 1000.0)
        feat_vectors.append(fv)

    # 2. Model predict_proba timing (given feature vector)
    model_times = []
    for fv in feat_vectors:
        t0 = time.perf_counter()
        _ = detector.model.predict_proba([fv])
        t1 = time.perf_counter()
        model_times.append((t1 - t0) * 1000.0)

    # 3. Full Detector.predict timing (ML path: normalization + audit + ftr_ext + ML)
    full_ml_times = []
    for u in sample_ml_urls:
        t0 = time.perf_counter()
        _ = detector.predict(u)
        t1 = time.perf_counter()
        full_ml_times.append((t1 - t0) * 1000.0)

    # 4. Whitelist path timing
    wl_domains = list(whitelist)
    if not wl_domains:
        wl_domains = ["google.com", "microsoft.com", "apple.com"]
    # Generate 1,000 queries to whitelisted domains
    wl_queries = [f"https://www.{wl_domains[i % len(wl_domains)]}/" for i in range(1000)]
    full_wl_times = []
    for u in wl_queries:
        t0 = time.perf_counter()
        _ = detector.predict(u)
        t1 = time.perf_counter()
        full_wl_times.append((t1 - t0) * 1000.0)

    results = {
        "n_samples": len(sample_ml_urls),
        "feature_extraction": calc_stats(feat_times),
        "model_predict_proba": calc_stats(model_times),
        "detector_predict_ml_path": calc_stats(full_ml_times),
        "detector_predict_whitelist_path": calc_stats(full_wl_times),
    }

    print("\n=== LATENCY BENCHMARK RESULTS (in ms) ===")
    print(f"Feature Extraction:            mean={results['feature_extraction']['mean_ms']:.3f}ms, p50={results['feature_extraction']['p50_ms']:.3f}ms, p95={results['feature_extraction']['p95_ms']:.3f}ms, p99={results['feature_extraction']['p99_ms']:.3f}ms")
    print(f"Model predict_proba:           mean={results['model_predict_proba']['mean_ms']:.3f}ms, p50={results['model_predict_proba']['p50_ms']:.3f}ms, p95={results['model_predict_proba']['p95_ms']:.3f}ms, p99={results['model_predict_proba']['p99_ms']:.3f}ms")
    print(f"Full Detector (ML Path):       mean={results['detector_predict_ml_path']['mean_ms']:.3f}ms, p50={results['detector_predict_ml_path']['p50_ms']:.3f}ms, p95={results['detector_predict_ml_path']['p95_ms']:.3f}ms, p99={results['detector_predict_ml_path']['p99_ms']:.3f}ms")
    print(f"Full Detector (Whitelist Path):mean={results['detector_predict_whitelist_path']['mean_ms']:.3f}ms, p50={results['detector_predict_whitelist_path']['p50_ms']:.3f}ms, p95={results['detector_predict_whitelist_path']['p95_ms']:.3f}ms, p99={results['detector_predict_whitelist_path']['p99_ms']:.3f}ms")

    out_file = os.path.join(ROOT, "reports", "latency.json")
    with open(out_file, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nSaved latency report to {out_file}")


if __name__ == "__main__":
    main()
