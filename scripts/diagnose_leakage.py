"""Check whether high accuracy comes from dataset artifacts instead of real phishing signals.
Run:  python scripts/diagnose_leakage.py --data data/dataset.csv
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score
from src.ftr_ext import FEATURE_NAMES, feature_vector, registered_domain, host_only_url

ap = argparse.ArgumentParser(); ap.add_argument("--data", default="data/dataset.csv"); a = ap.parse_args()
df = pd.read_csv(a.data)[["url", "label"]].dropna().drop_duplicates("url")
y = df.label.values; groups = df.url.map(registered_domain).values


def split_score(df_subset, cols=None, n_est=300):
    X = np.array([feature_vector(u) for u in df_subset.url])
    if cols is not None:
        X = X[:, [FEATURE_NAMES.index(c) for c in cols]]
    y_sub = df_subset.label.astype(int).values
    groups_sub = df_subset.url.map(registered_domain).values
    tr, te = next(GroupShuffleSplit(1, test_size=0.2, random_state=42).split(X, y_sub, groups_sub))
    m = RandomForestClassifier(n_est, n_jobs=-1, random_state=42).fit(X[tr], y_sub[tr])
    return accuracy_score(y_sub[te], m.predict(X[te]))

artifact = ["path_length", "query_length", "num_slashes", "uses_https", "double_slash_in_path"]
print("1) Accuracy using ONLY path/scheme features (carry no real host information):")
print(f"   {split_score(df, artifact):.4f}   <- near 0.9+ means the dataset is leaking")
print("2) Accuracy using ALL features on full URLs:       %.4f" % split_score(df))

# Host-only procedure matching train.py:
df_host = df.copy()
df_host["url"] = df_host.url.map(host_only_url)
df_host = df_host.drop_duplicates(["url", "label"])
df_host = df_host.drop_duplicates("url", keep=False)   # drop hosts that appear with both labels

print("3) Accuracy using ALL features on host-only URLs:  %.4f   <- fairer estimate"
      % split_score(df_host))
print(f"   (evaluated on {len(df_host)} unique hosts with conflicting labels removed)")
print("\nPath-vs-label table (share of URLs that have a path beyond '/'):")
has_path = df.url.map(lambda u: len(u.split("://", 1)[-1].split("/", 1)[-1]) > 0 if "/" in u.split("://", 1)[-1] else False)
print(pd.crosstab(df.label.map({0: "legit", 1: "phishing"}), has_path.map({True: "has path", False: "no path"}), normalize="index").round(3).to_string())
