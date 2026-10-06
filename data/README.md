# Dataset Documentation

This directory contains URL data sources, the curated evaluation dataset, and the trusted-domain whitelist used by the Phishing Website Detection system (IEEE CS Bangalore Chapter internship, Project P98).

> **Important Note:** PhishTank is a live threat intelligence feed that changes continuously throughout the day as new phishing URLs are reported and verified. Therefore, subsequent downloads from PhishTank will contain different URL snapshots.

---

## Data Sources & Download URLs

1. **PhishTank** (Phishing URLs):
   - **Source Page:** [PhishTank Developer Info](https://phishtank.org/developer_info.php)
   - **Direct Download URL:** `https://data.phishtank.com/data/online-valid.csv`
   - **Download Date:** 2026-10-05
   - **Format:** CSV with fields `phish_id`, `url`, `phish_detail_url`, `submission_time`, `verified`, `verification_time`, `online`, `target`.
   
2. **Tranco** (Legitimate URLs):
   - **Source Page:** [Tranco Research List](https://tranco-list.eu)
   - **Direct Download URL:** `https://tranco-list.eu/top-1m.csv.zip`
   - **Download Date:** 2026-10-05
   - **Format:** CSV without header: `rank,domain` (Top 1 Million domains ranked by traffic).

---

## File Integrity & Row Counts

The following checksums and statistics were measured on the local files:

| File | Row Count (Lines) | Size (Bytes) | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| `data/online-valid.csv` | 72,160 | 13,797,488 | `59b2ece0198d02159163cbddf64620e40982daaae59537758c28a14a1ce1f9f9` |
| `data/top-1m.csv` | 1,000,000 | 22,606,903 | `23165e5e9e9ec2b6b186fb092c285f1943d51d25fb48d27d7fe1e0cad0bca959` |
| `data/dataset.csv` | 40,001 | 1,704,510 | `00695fde7357aa15f39dd2c167d375012517c04bd9e6c4af0ebc8a5f61257c45` |
| `data/trusted_domains.txt` | 22 | 318 | `c747f679ef6f0f0848ad4765320a507971addd409dd8a954acc729caf535e505` |

### Class Distribution in `data/dataset.csv`
- Total samples: 40,000 URLs (excluding CSV header)
- Phishing (`label = 1`): 20,000
- Legitimate (`label = 0`): 20,000
- Class balance: exactly 50% / 50%

---

## Dataset Rebuild Command

To reproduce `data/dataset.csv` from the raw downloads, run:

```powershell
python scripts/prepare_dataset.py --phishtank data/online-valid.csv --tranco data/top-1m.csv --n 20000 --out data/dataset.csv
```

*Note: Per project rules, `data/dataset.csv` must not be regenerated or modified once created for experimental consistency.*

---

## Secondary Independent Evaluation Dataset (Cross-Dataset)

As required by Phase 2d and to evaluate out-of-distribution robustness against dataset artifacts, a second independently labeled benchmark was used:

- **Dataset Name:** ISCX-URL2016 / Kaggle Malicious URLs Dataset (Manu Siddhartha / sid321axn)
- **Literature Reference:** Survey arXiv:2504.16449 (Tian et al. 2025: *"From Past to Present: A Survey of Malicious URL Detection Techniques, Datasets and Code Repositories"*) and Sahoo et al. 2017 (arXiv:1701.07179)
- **Source Direct URL:** `https://raw.githubusercontent.com/idankinderman/Malicious_URL_Detection/main/malicious_phish_CSV.csv`
- **License:** CC0: Public Domain / Open Database License
- **Full File Size:** 45,702,719 bytes (651,191 raw URLs)
- **Sampled Subset:** `data/second_dataset.csv` (10,000 URLs: 5,000 benign, 5,000 phishing; 518,469 bytes)
- **Label Definition:**
  - `benign` = 0 (Legitimate)
  - `phishing` = 1 (Phishing)
- **Key Characteristic:** 87.94% of legitimate URLs in this dataset contain real paths beyond the root (`/`), enabling fair assessment of full-URL models and real-world cross-dataset generalization.
- **Evaluation Script:** `python scripts/cross_dataset_eval.py` (saves to `reports/cross_dataset.json`)

