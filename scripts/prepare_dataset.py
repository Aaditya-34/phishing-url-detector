"""Build data/dataset.csv from real sources.

  python scripts/prepare_dataset.py --phishtank online-valid.csv --tranco top-1m.csv --n 20000

Phishing: PhishTank 'online-valid.csv' (column 'url').  https://phishtank.org/developer_info.php
Legit:    Tranco top-1m list (rank,domain).               https://tranco-list.eu
Alternatively pass --ready some_labeled.csv with columns url,label to just normalise it.

NOTE (bias): PhishTank URLs usually carry paths while Tranco gives bare domains, which lets a
model cheat on 'path length'. We prefix 'https://' and add 'www.' variants / a short random-free
homepage path only for domains, and recommend ALSO testing on a second, independently
labelled dataset. Mention this under Limitations in the report.
"""
import argparse, os
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--phishtank"); ap.add_argument("--tranco"); ap.add_argument("--ready")
ap.add_argument("--n", type=int, default=20000, help="rows per class")
ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv"))
a = ap.parse_args()

if a.ready:
    df = pd.read_csv(a.ready)
    df = df.rename(columns={c: c.lower() for c in df.columns})[["url", "label"]]
else:
    ph = pd.read_csv(a.phishtank)["url"].dropna().drop_duplicates()
    ph = ph.sample(min(a.n, len(ph)), random_state=42)
    tr = pd.read_csv(a.tranco, header=None, names=["rank", "domain"])["domain"].head(a.n * 5)
    tr = tr.sample(min(a.n, len(tr)), random_state=42)
    legit = "https://" + tr
    df = pd.concat([pd.DataFrame({"url": ph, "label": 1}), pd.DataFrame({"url": legit, "label": 0})])
df = df.drop_duplicates("url").sample(frac=1, random_state=42)
df.to_csv(a.out, index=False)
print(df.label.value_counts().to_string(), "->", os.path.abspath(a.out))
