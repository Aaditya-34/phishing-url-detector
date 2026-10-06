"""Train + evaluate classifiers. Usage: python -m src.train --data data/dataset.csv

Dataset CSV columns: url,label   (label: 1 = phishing, 0 = legitimate)
Outputs: models/model.pkl, reports/metrics.json and report plots.
"""
import argparse, json, os, time
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, cross_val_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from src.ftr_ext import FEATURE_NAMES, feature_vector, registered_domain, host_only_url

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(ROOT, "data", "dataset.csv"))
    ap.add_argument("--max-rows", type=int, default=0, help="optional cap (for quick runs)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--host-only", action="store_true",
                    help="use only scheme+hostname (removes path/scheme dataset artifacts)")
    ap.add_argument("--deploy", action="store_true", help="also write models/model.pkl used by the app")
    a = ap.parse_args()

    df = pd.read_csv(a.data)[["url", "label"]].dropna().drop_duplicates("url")
    if a.max_rows and len(df) > a.max_rows:
        df = df.sample(a.max_rows, random_state=a.seed)
    tag = "host_only" if a.host_only else "full_url"
    if a.host_only:
        df["url"] = df.url.map(host_only_url)
        before = len(df)
        df = df.drop_duplicates(["url", "label"])
        df = df.drop_duplicates("url", keep=False)   # drop hosts that appear with both labels
        print(f"host-only mode: {before} -> {len(df)} unique hosts")
    print(f"Mode: {tag}")
    print(f"Dataset: {os.path.basename(a.data)} | {len(df)} unique URLs | "
          f"phishing={int((df.label == 1).sum())} legit={int((df.label == 0).sum())}")

    t0 = time.time()
    X = np.array([feature_vector(u) for u in df.url])
    y = df.label.astype(int).values
    groups = df.url.map(registered_domain).values
    print(f"Feature extraction: {time.time() - t0:.1f}s")

    # group split: the same registered domain never appears in both train and test
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=a.seed)
    tr, te = next(gss.split(X, y, groups))
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=a.seed),
        "SVM (RBF)": make_pipeline(StandardScaler(), CalibratedClassifierCV(SVC(random_state=a.seed), cv=3, ensemble=False)),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
    }
    results, fitted = {}, {}
    for name, m in models.items():
        t = time.time(); m.fit(Xtr, ytr); train_s = time.time() - t
        pred = m.predict(Xte); prob = m.predict_proba(Xte)[:, 1]
        results[name] = {
            "accuracy": accuracy_score(yte, pred), "precision": precision_score(yte, pred),
            "recall": recall_score(yte, pred), "f1": f1_score(yte, pred),
            "roc_auc": roc_auc_score(yte, prob), "false_positive_rate":
                float(((pred == 1) & (yte == 0)).sum() / max((yte == 0).sum(), 1)),
            "train_seconds": round(train_s, 2),
            "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        }
        fitted[name] = (m, prob)
        print(f"{name:20s} acc={results[name]['accuracy']:.4f} f1={results[name]['f1']:.4f} "
              f"auc={results[name]['roc_auc']:.4f}")

    rf = fitted["Random Forest"][0]
    cv = cross_val_score(RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=a.seed),
                         Xtr, ytr, cv=5, scoring="f1")
    imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda t: -t[1])

    os.makedirs(os.path.join(ROOT, "models"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    bundle = {"model": rf, "features": FEATURE_NAMES, "host_only": a.host_only}
    joblib.dump(bundle, os.path.join(ROOT, "models", f"model_{tag}.pkl"), compress=3)
    if a.deploy:
        joblib.dump(bundle, os.path.join(ROOT, "models", "model.pkl"), compress=3)

    metrics = {"mode": tag, "dataset": os.path.basename(a.data), "n_urls": int(len(df)),
               "n_phishing": int((df.label == 1).sum()), "n_legit": int((df.label == 0).sum()),
               "n_train": int(len(tr)), "n_test": int(len(te)), "n_features": len(FEATURE_NAMES),
               "split": "group split by registered domain, 80/20, seed %d" % a.seed,
               "cv_f1_mean_rf": float(cv.mean()), "cv_f1_std_rf": float(cv.std()),
               "results": results, "top_features": [(k, float(v)) for k, v in imp[:10]]}
    with open(os.path.join(ROOT, "reports", f"metrics_{tag}.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    out = os.path.join(ROOT, "reports")
    cm = np.array(results["Random Forest"]["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(4.2, 3.8)); ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=13)
    ax.set_xticks([0, 1], ["Legit", "Phishing"]); ax.set_yticks([0, 1], ["Legit", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion Matrix (Random Forest)")
    fig.tight_layout(); fig.savefig(f"{out}/{tag}_confusion_matrix.png", dpi=200); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4.2)); top = imp[:10][::-1]
    ax.barh([k for k, _ in top], [v for _, v in top], color="#2563eb")
    ax.set_title("Top 10 Feature Importances (Random Forest)"); ax.set_xlabel("Importance")
    fig.tight_layout(); fig.savefig(f"{out}/{tag}_feature_importance.png", dpi=200); plt.close(fig)

    fig, ax = plt.subplots(figsize=(5, 4))
    for name, (_, prob) in fitted.items():
        fpr, tpr, _ = roc_curve(yte, prob)
        ax.plot(fpr, tpr, label=f"{name} (AUC={results[name]['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=0.8); ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate"); ax.set_title("ROC Curves"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/{tag}_roc_curves.png", dpi=200); plt.close(fig)

    names = list(results); fig, ax = plt.subplots(figsize=(6.5, 4)); w = 0.2
    for i, k in enumerate(["accuracy", "precision", "recall", "f1"]):
        ax.bar(np.arange(len(names)) + i * w, [results[n][k] for n in names], w, label=k)
    ax.set_xticks(np.arange(len(names)) + 1.5 * w, names); ax.set_ylim(0.5, 1.0)
    ax.set_title("Model Comparison"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/{tag}_model_comparison.png", dpi=200); plt.close(fig)
    print(f"Saved models/model_{tag}.pkl, reports/metrics_{tag}.json, reports/{tag}_*.png" + (" and models/model.pkl (deployed)" if a.deploy else ""))


if __name__ == "__main__":
    main()
