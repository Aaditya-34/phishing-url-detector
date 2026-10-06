"""Cross-dataset evaluation on an independent public URL dataset.
Dataset: ISCX-URL2016 / Kaggle Malicious URLs (Manu Siddhartha / sid321axn)
Reference: Survey arXiv:2504.16449 (Tian et al. 2025)
Usage: python scripts/cross_dataset_eval.py
Saves results to reports/cross_dataset.json
"""
import csv
import io
import json
import os
import sys
import urllib.request
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ftr_ext import FEATURE_NAMES, feature_vector, host_only_url, registered_domain, normalize_url
from src.predictor import Detector

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_URL = "https://raw.githubusercontent.com/idankinderman/Malicious_URL_Detection/main/malicious_phish_CSV.csv"
LOCAL_CSV = os.path.join(ROOT, "data", "second_dataset.csv")


def download_or_load_dataset(n_per_class=5000):
    if os.path.exists(LOCAL_CSV):
        print(f"Loading cached second dataset from {LOCAL_CSV}")
        return pd.read_csv(LOCAL_CSV)

    print(f"Downloading sample of {n_per_class*2} URLs from {RAW_URL}...")
    req = urllib.request.Request(RAW_URL, headers={"User-Agent": "Mozilla/5.0"})
    benign, phish = [], []
    with urllib.request.urlopen(req) as resp:
        reader = csv.reader(io.TextIOWrapper(resp, encoding="utf-8", errors="ignore"))
        for row in reader:
            if len(row) < 2:
                continue
            u, lbl = row[0].strip(), row[1].strip().lower()
            if lbl == "benign" and len(benign) < n_per_class:
                benign.append(u)
            elif lbl == "phishing" and len(phish) < n_per_class:
                phish.append(u)
            if len(benign) >= n_per_class and len(phish) >= n_per_class:
                break

    df_benign = pd.DataFrame({"url": benign, "label": 0})
    df_phish = pd.DataFrame({"url": phish, "label": 1})
    df = pd.concat([df_benign, df_phish]).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(LOCAL_CSV, index=False)
    print(f"Saved {len(df)} samples to {LOCAL_CSV}")
    return df


def main():
    print("=== CROSS-DATASET EVALUATION ===")
    df2 = download_or_load_dataset(n_per_class=5000)
    # Ensure scheme
    df2["url"] = df2["url"].map(normalize_url)

    # Check path presence in benign URLs
    benign_urls = df2[df2.label == 0]["url"]
    has_path = [len(u.split("://", 1)[-1].split("/", 1)[-1]) > 0 if "/" in u.split("://", 1)[-1] else False for u in benign_urls]
    legit_path_ratio = float(sum(has_path) / len(has_path))
    print(f"Second dataset legit URLs with path: {sum(has_path)}/{len(has_path)} ({legit_path_ratio*100:.1f}%)")

    # 1. EVALUATION 1: Cross-dataset test using our deployed host-only model
    print("\n--- Part 1: Deployed Host-Only Model Tested on Second Dataset Hostnames ---")
    detector = Detector()

    # Prepare second dataset in host-only mode
    df2_host = df2.copy()
    df2_host["url"] = df2_host["url"].map(host_only_url)
    df2_host = df2_host.drop_duplicates(["url", "label"])
    df2_host = df2_host.drop_duplicates("url", keep=False)
    print(f"Second dataset unique hosts: {len(df2_host)} (phishing={int((df2_host.label == 1).sum())}, legit={int((df2_host.label == 0).sum())})")

    X2_host = np.array([feature_vector(u) for u in df2_host["url"]])
    y2_host = df2_host["label"].astype(int).values

    class_idx = list(detector.model.classes_).index(1)
    prob_cross = detector.model.predict_proba(X2_host)[:, class_idx]
    pred_cross = (prob_cross >= 0.5).astype(int)

    cross_metrics = {
        "n_samples": int(len(df2_host)),
        "n_phishing": int((df2_host.label == 1).sum()),
        "n_legit": int((df2_host.label == 0).sum()),
        "accuracy": round(float(accuracy_score(y2_host, pred_cross)), 4),
        "precision": round(float(precision_score(y2_host, pred_cross, zero_division=0)), 4),
        "recall": round(float(recall_score(y2_host, pred_cross)), 4),
        "f1": round(float(f1_score(y2_host, pred_cross)), 4),
        "roc_auc": round(float(roc_auc_score(y2_host, prob_cross)), 4),
        "confusion_matrix": confusion_matrix(y2_host, pred_cross).tolist(),
    }
    print(f"Cross-Dataset Host-Only: acc={cross_metrics['accuracy']:.4f}, f1={cross_metrics['f1']:.4f}, roc_auc={cross_metrics['roc_auc']:.4f}")

    # 2. EVALUATION 2: Full-URL model trained and tested within the second dataset
    print("\n--- Part 2: Full-URL RF Model Trained & Tested Within Second Dataset ---")
    # Only if legit URLs contain real paths
    within_metrics = {}
    if legit_path_ratio > 0.5:
        df2_full = df2.drop_duplicates("url").copy()
        X2_full = np.array([feature_vector(u) for u in df2_full["url"]])
        y2_full = df2_full["label"].astype(int).values
        groups2 = df2_full["url"].map(registered_domain).values

        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        tr, te = next(gss.split(X2_full, y2_full, groups2))
        Xtr, Xte, ytr, yte = X2_full[tr], X2_full[te], y2_full[tr], y2_full[te]

        rf2 = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
        rf2.fit(Xtr, ytr)
        pred2 = rf2.predict(Xte)
        prob2 = rf2.predict_proba(Xte)[:, 1]

        within_metrics = {
            "n_total": int(len(df2_full)),
            "n_train": int(len(tr)),
            "n_test": int(len(te)),
            "legit_with_path_ratio": round(legit_path_ratio, 4),
            "accuracy": round(float(accuracy_score(yte, pred2)), 4),
            "precision": round(float(precision_score(yte, pred2)), 4),
            "recall": round(float(recall_score(yte, pred2)), 4),
            "f1": round(float(f1_score(yte, pred2)), 4),
            "roc_auc": round(float(roc_auc_score(yte, prob2)), 4),
            "confusion_matrix": confusion_matrix(yte, pred2).tolist(),
        }
        print(f"Within Second Dataset Full-URL: acc={within_metrics['accuracy']:.4f}, f1={within_metrics['f1']:.4f}, roc_auc={within_metrics['roc_auc']:.4f}")
    else:
        print("Skipping full-URL within second dataset: legit URLs do not contain paths.")

    report = {
        "dataset_name": "ISCX-URL2016 / Kaggle Malicious URLs Dataset (Manu Siddhartha / sid321axn)",
        "source_url": RAW_URL,
        "license": "CC0: Public Domain",
        "description": "Independently curated benchmark dataset containing deep URLs for both legitimate and phishing classes.",
        "label_definition": {"benign": 0, "phishing": 1},
        "legit_with_path_pct": round(legit_path_ratio * 100, 2),
        "cross_dataset_host_only_eval": cross_metrics,
        "within_second_dataset_full_url_eval": within_metrics,
    }

    out_file = os.path.join(ROOT, "reports", "cross_dataset.json")
    with open(out_file, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nSaved cross-dataset evaluation report to {out_file}")


if __name__ == "__main__":
    main()
