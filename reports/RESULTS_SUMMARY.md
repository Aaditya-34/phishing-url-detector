# Results Summary & Experimental Evaluation

**Project:** Phishing Website Detection using URL-Based Feature Analysis  
**Affiliation:** IEEE CS Bangalore Chapter Internship & Mentorship Program 2026 — Project P98  
**Team:** Naina Ramesh, Ritesh Choudhary, Deepak Vaishnav, Aaditya Raaj Pandit  
**Mentor:** Dr. V. Muthu Ganesh, Presidency University  

This document serves as the single source of truth for all experimental numbers, validation metrics, benchmarks, and environment metadata produced across the evaluation pipeline. Every metric recorded below is derived directly from generated run artifacts.

---

## 1. Dataset Statistics & Partitioning

Source raw datasets downloaded on **2026-10-05**:
- **PhishTank:** `data/online-valid.csv` (72,160 rows, 13,797,488 bytes, SHA-256: `59b2ece0198d02159163cbddf64620e40982daaae59537758c28a14a1ce1f9f9`)
- **Tranco:** `data/top-1m.csv` (1,000,000 rows, 22,606,903 bytes, SHA-256: `23165e5e9e9ec2b6b186fb092c285f1943d51d25fb48d27d7fe1e0cad0bca959`)
- **Evaluation Dataset:** `data/dataset.csv` (40,001 rows including header, 1,704,510 bytes, SHA-256: `00695fde7357aa15f39dd2c167d375012517c04bd9e6c4af0ebc8a5f61257c45`)
- **Trusted Whitelist:** `data/trusted_domains.txt` (22 exact registered domains, 318 bytes, SHA-256: `c747f679ef6f0f0848ad4765320a507971addd409dd8a954acc729caf535e505`)

### Data Splits & Sizes

| Metric / Parameter | Full-URL Mode (`metrics_full_url.json`) | Host-Only Mode (`metrics_host_only.json`) |
| :--- | :--- | :--- |
| **Total URLs Analyzed** | 40,000 | 31,717 (unique hosts, conflicting labels dropped) |
| **Phishing URLs (`label = 1`)** | 20,000 | 11,741 |
| **Legitimate URLs (`label = 0`)** | 20,000 | 19,976 |
| **Class Balance** | 50.0% / 50.0% | 37.02% Phishing / 62.98% Legitimate |
| **Feature Dimension** | 27 URL-derived features | 27 URL-derived features |
| **Split Strategy** | Group split by registered domain (seed 42) | Group split by registered domain (seed 42) |
| **Split Ratio** | 80% Train / 20% Test | 80% Train / 20% Test |
| **Training Set Size** | 28,954 | 25,809 |
| **Test Set Size** | 11,046 | 5,908 |

---

## 2. Dataset Leakage Diagnostic

The full-URL approach exhibits artificial accuracy inflation due to collection methodology bias: Tranco legitimate entries represent domain origins without URL paths, whereas 64.9% of active PhishTank phishing URLs contain directory paths and parameters.

Exact output from `reports/leakage_diagnostic.txt`:
```text
1) Accuracy using ONLY path/scheme features (carry no real host information):
   0.9901   <- near 0.9+ means the dataset is leaking
2) Accuracy using ALL features on full URLs:       0.9975
3) Accuracy using ALL features on host-only URLs:  0.9348   <- fairer estimate
   (evaluated on 31717 unique hosts with conflicting labels removed)

Path-vs-label table (share of URLs that have a path beyond '/'):
url       has path  no path
label                      
legit        0.000    1.000
phishing     0.649    0.351
```

---

## 3. Comparative Model Performance Metrics

### 3.1 Host-Only Evaluation (Realistic / Production Baseline — Deployed in `models/model.pkl`)
- **Stratified/Group CV F1 (Random Forest):** 0.9098 ± 0.0068 (Mean: 0.90977, Std: 0.00677)

| Classifier / Strategy | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | Train Time (s) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest (ML Alone)** | 0.9348 | 0.9470 | 0.8450 | 0.8931 | 0.9448 | 0.0225 | 0.70 |
| **SVM (RBF Kernel)** | 0.9369 | 0.9799 | 0.8208 | 0.8933 | 0.9329 | 0.0080 | 13.88 |
| **Logistic Regression**| 0.9328 | 0.9754 | 0.8119 | 0.8861 | 0.9480 | 0.0097 | 0.06 |
| **Hybrid (RF OR Rule >= 50)** | **0.9348** | **0.9470** | **0.8450** | **0.8931** | **N/A** | **0.0225** | **—** |

*Hybrid Evaluation Notes (`reports/hybrid.json`):*
- Evaluated on the exact same held-out test split ($N = 5,908$).
- Flagged rule: `flagged = (ML phishing with threshold 0.5) OR (rule score >= 50)`.
- **Hybrid Accuracy:** 0.9348 (93.48%)
- **Hybrid Precision:** 0.9470 (94.70%)
- **Hybrid Recall:** 0.8450 (84.50%)
- **Hybrid F1-Score:** 0.8931
- **Hybrid False Positive Rate (FPR):** 0.0225 (2.25%)
- **Phishing Recall of ML Model Alone:** 0.8450 (84.50%)
- On this normalized host-only test set, rule score $\ge 50$ flags were 0 (both ML and hybrid confusion matrices: $TN = 3915, FP = 90, FN = 295, TP = 1608$).

#### Host-Only Confusion Matrices (Test N = 5,908)
- **Random Forest:**  
  $\begin{bmatrix} TN: 3915 & FP: 90 \\ FN: 295 & TP: 1608 \end{bmatrix}$
- **Hybrid Strategy:**  
  $\begin{bmatrix} TN: 3915 & FP: 90 \\ FN: 295 & TP: 1608 \end{bmatrix}$
- **SVM (RBF):**  
  $\begin{bmatrix} TN: 3973 & FP: 32 \\ FN: 341 & TP: 1562 \end{bmatrix}$
- **Logistic Regression:**  
  $\begin{bmatrix} TN: 3966 & FP: 39 \\ FN: 358 & TP: 1545 \end{bmatrix}$

---

### 3.2 Full-URL Evaluation (Biased / Laboratory Setting)
- **Stratified/Group CV F1 (Random Forest):** 0.9965 ± 0.0007 (Mean: 0.99655, Std: 0.00071)

| Classifier | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | Train Time (s) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | 0.9975 | 0.9993 | 0.9967 | 0.9980 | 0.9988 | 0.0013 | 0.71 |
| **SVM (RBF Kernel)** | 0.9968 | 0.9984 | 0.9966 | 0.9975 | 0.9988 | 0.0028 | 4.28 |
| **Logistic Regression**| 0.9974 | 0.9999 | 0.9960 | 0.9979 | 0.9990 | 0.0003 | 0.04 |

#### Full-URL Confusion Matrices (Test N = 11,046)
- **Random Forest:**  
  $\begin{bmatrix} TN: 3977 & FP: 5 \\ FN: 23 & TP: 7041 \end{bmatrix}$
- **SVM (RBF):**  
  $\begin{bmatrix} TN: 3971 & FP: 11 \\ FN: 24 & TP: 7040 \end{bmatrix}$
- **Logistic Regression:**  
  $\begin{bmatrix} TN: 3981 & FP: 1 \\ FN: 28 & TP: 7036 \end{bmatrix}$

---

## 4. Feature Importance Rankings (Top 10)

Feature importances derived from the Gini impurity reduction of the trained Random Forest models:

### Host-Only Model (`metrics_host_only.json`)
1. `num_subdomains`: **0.3042** (30.42%)
2. `hostname_length`: **0.1657** (16.57%)
3. `url_length`: **0.1451** (14.51%)
4. `num_dots`: **0.1425** (14.25%)
5. `domain_entropy`: **0.0501** (5.01%)
6. `tld_length`: **0.0362** (3.62%)
7. `num_digits`: **0.0289** (2.89%)
8. `digit_ratio`: **0.0253** (2.53%)
9. `num_hyphens`: **0.0250** (2.50%)
10. `letter_ratio`: **0.0235** (2.35%)

### Full-URL Model (`metrics_full_url.json`)
*(Illustrating artifact bias where path features dominate over domain features)*
1. `num_slashes`: **0.2705** (27.05%)
2. `path_length`: **0.2345** (23.45%)
3. `url_length`: **0.1453** (14.53%)
4. `num_subdomains`: **0.1150** (11.50%)
5. `num_dots`: **0.0478** (4.78%)
6. `num_digits`: **0.0388** (3.88%)
7. `hostname_length`: **0.0319** (3.19%)
8. `digit_ratio`: **0.0266** (2.66%)
9. `num_hyphens`: **0.0164** (1.64%)
10. `uses_https`: **0.0151** (1.51%)

---

## 5. System Latency Benchmark

Measured across 1,000 held-out URLs using `scripts/benchmark_latency.py` (`reports/latency.json`):

| Pipeline Stage | Mean (ms) | p50 Median (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Feature Extraction** | 0.0239 | 0.0222 | 0.0280 | 0.0393 | 0.0188 | 0.4420 |
| **Model Inference (`predict_proba`)** | 26.6715 | 25.2045 | 35.9457 | 37.8939 | 23.7934 | 58.8810 |
| **Full Detector (ML Path)** | 26.9918 | 25.4720 | 36.2524 | 40.6607 | 24.1731 | 63.2636 |
| **Detector (Whitelist Path)** | 0.0307 | 0.0295 | 0.0337 | 0.0432 | 0.0272 | 0.1930 |

*Key finding: The exact whitelist path executes in ~0.03 ms, bypassing the ML inference overhead of ~27 ms for known high-reputation domains.*

---

## 6. Adversarial Robustness Assessment

Evaluated on 1,609 correctly classified phishing hosts from the held-out test partition using lexical perturbation transforms (`scripts/robustness_test.py`, `reports/robustness.json`):

> **Note:** Evaluates robustness to simple lexical evasion only, not an active adaptive adversary.

| Perturbation Transform | Description | Detected / Total | Detection Rate (%) | Evasion Rate (%) |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline (Unperturbed)** | Clean hold-out phishing hosts | 1,609 / 1,609 | 100.00% | 0.00% |
| **Add `www` Subdomain** | Prepend `www.` or replace with `www2` | 1,609 / 1,609 | 100.00% | 0.00% |
| **Insert One Hyphen** | Insert hyphen into registered domain | 1,555 / 1,609 | 96.64% | 3.36% |
| **Swap TLD to `.com`** | Substitute original TLD with `.com` | 1,555 / 1,609 | 96.64% | 3.36% |
| **Append Numeric Label** | Append `-01` suffix to domain label | 1,541 / 1,609 | 95.77% | 4.23% |
| **Lengthen Subdomain** | Prepend `portal.` sub-label | 1,609 / 1,609 | 100.00% | 0.00% |

---

## 7. Cross-Dataset Evaluation

To validate out-of-distribution generalization against dataset artifacts, evaluation was conducted against an independent external benchmark (`reports/cross_dataset.json`):

- **Exact Dataset Name:** `ISCX-URL2016 / Kaggle Malicious URLs Dataset (Manu Siddhartha / sid321axn)`
- **Literature Reference:** Survey arXiv:2504.16449 (Tian et al. 2025: *"From Past to Present: A Survey of Malicious URL Detection Techniques, Datasets and Code Repositories"*) and Sahoo et al. 2017 (arXiv:1701.07179)
- **Source Direct URL:** `https://raw.githubusercontent.com/idankinderman/Malicious_URL_Detection/main/malicious_phish_CSV.csv`
- **License Status:** `CC0: Public Domain / Open Database License`
- **Path Characteristics:** 87.94% of legitimate URLs in this dataset contain real paths beyond the root (`/`).

### 7.1 Cross-Dataset Evaluation (Trained on Primary Host-Only, Tested on ISCX Hosts)
- **Test Samples:** 7,517 unique hosts (4,507 phishing, 3,010 legitimate)
- **Cross-Dataset Accuracy:** **59.01%** (0.5901)
- **Precision:** 0.7386 (73.86%)
- **Recall:** 0.4897 (48.97%)
- **F1-Score:** 0.5889 (58.89%)
- **ROC-AUC:** 0.6164 (61.64%)
- **Confusion Matrix:**  
  $\begin{bmatrix} TN: 2229 & FP: 781 \\ FN: 2300 & TP: 2207 \end{bmatrix}$

*Key finding: The cross-dataset accuracy was 59.01%, clearly demonstrating that models trained solely on a single feed suffer from domain distribution shifts when evaluated on out-of-distribution hostnames.*

### 7.2 Within-Dataset Full-URL Benchmark (Trained & Tested on Second Dataset)
- **Total Samples:** 10,000 URLs (7,965 train / 2,035 test; 87.94% legit URLs have paths)
- **Accuracy:** 0.8865 (88.65%)
- **Precision:** 0.9636 (96.36%)
- **Recall:** 0.8255 (82.55%)
- **F1-Score:** 0.8892 (88.92%)
- **ROC-AUC:** 0.9147 (91.47%)
- **Confusion Matrix:**  
  $\begin{bmatrix} TN: 877 & FP: 35 \\ FN: 196 & TP: 927 \end{bmatrix}$

---

## 8. Runtime Environment & Dependency Versions (Project Virtualenv)

Verified and measured directly inside the project's permanent virtual environment (`c:\Users\aadit\Desktop\MyAadiProjects\IEEE Internship Project 2026\phishing-url-detector\venv\Scripts\python.exe`):
- **Python Executable:** `c:\Users\aadit\Desktop\MyAadiProjects\IEEE Internship Project 2026\phishing-url-detector\venv\Scripts\python.exe`
- **Python Version:** `3.12.10 (tags/v3.12.10:0cc8128, Apr 8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]`
- **flask:** `3.1.3`
- **scikit-learn:** `1.9.1`
- **pandas:** `3.0.6`
- **numpy:** `2.5.3`
- **tldextract:** `5.4.0`
- **joblib:** `1.6.0`
- **pytest:** `9.1.1`

---

## 9. Test Suite Verification Summary

Executing `python -m pytest -q tests`:
```text
..................                                                       [100%]
18 passed in 1.95s
```

All 18 integration and unit tests passed, covering:
1. Feature vector dimensionality and ordering (`27` features)
2. IP address, `@` symbol, and scheme detection
3. Subdomain extraction and multi-level registered domain extraction
4. Resilient handling of missing schemes and junk inputs
5. Risk heuristic level assignment
6. `host_only_url` scheme and path stripping, IP addresses, and junk inputs
7. Whitelist exact-match semantics (`google.com.evil.tk` rejected from whitelist)
8. Flask `/predict` valid form submissions
9. Flask `/predict` empty input returns HTTP 400
10. Flask `/predict` length > 2048 chars returns HTTP 400
11. Flask `/predict` malformed URL avoids HTTP 500
12. Flask `/api/predict` valid URL and schema key validation (including `verdict`)
13. Flask `/api/predict` three-state overall verdict test (Whitelist $\to$ Legitimate, ML Phishing $\to$ Phishing, ML Legitimate with Rule Score $\ge 50$ $\to$ Suspicious)
14. Flask `/api/predict` empty JSON input returns HTTP 400
15. Flask `/api/predict` length > 2048 chars returns HTTP 400
16. Flask `/api/predict` malformed input avoids HTTP 500

---

## 10. Repository File Tree

```text
.
├── .env.example
├── .github
│   └── workflows
│       └── ci.yml
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── app.py
├── data
│   ├── README.md
│   ├── dataset.csv
│   ├── online-valid.csv
│   ├── second_dataset.csv
│   ├── top-1m.csv
│   └── trusted_domains.txt
├── docs
│   └── screenshots
│       ├── 01_home.png
│       ├── 02_result_legit.png
│       ├── 03_result_legit_ml.png
│       ├── 04_result_phishing.png
│       └── 05_reasons.png
├── models
│   ├── .gitkeep
│   ├── model.pkl
│   ├── model_full_url.pkl
│   └── model_host_only.pkl
├── reports
│   ├── .gitkeep
│   ├── RESULTS_SUMMARY.md
│   ├── confusion_matrix.png
│   ├── cross_dataset.json
│   ├── feature_importance.png
│   ├── full_url_confusion_matrix.png
│   ├── full_url_feature_importance.png
│   ├── full_url_model_comparison.png
│   ├── full_url_roc_curves.png
│   ├── host_only_confusion_matrix.png
│   ├── host_only_feature_importance.png
│   ├── host_only_model_comparison.png
│   ├── host_only_roc_curves.png
│   ├── hybrid.json
│   ├── latency.json
│   ├── leakage_diagnostic.txt
│   ├── metrics.json
│   ├── metrics_full_url.json
│   ├── metrics_host_only.json
│   ├── model_comparison.png
│   ├── robustness.json
│   └── roc_curves.png
├── requirements.txt
├── scripts
│   ├── benchmark_latency.py
│   ├── cross_dataset_eval.py
│   ├── diagnose_leakage.py
│   ├── make_demo_data.py
│   ├── prepare_dataset.py
│   └── robustness_test.py
├── src
│   ├── __init__.py
│   ├── ftr_ext.py
│   ├── predictor.py
│   ├── risk_analysis.py
│   └── train.py
├── static
│   └── style.css
├── templates
│   ├── base.html
│   ├── index.html
│   └── result.html
└── tests
    └── test_core.py
```

---

## 11. Inventory of Generated Figures & UI Screenshots

### Performance Plots & JSON Reports (`reports/`)
- `reports/hybrid.json`: Hybrid precision, recall, F1, FPR, and ML phishing recall alone.
- `reports/latency.json`: Feature extraction, model inference, full ML path, and whitelist latency benchmarks.
- `reports/cross_dataset.json`: Generalization evaluation on ISCX-URL2016 / Kaggle benchmark.
- `reports/robustness.json`: Lexical evasion rate benchmarks under string perturbations.
- `reports/host_only_model_comparison.png`: Accuracy, Precision, Recall, F1 across RF, SVM, and Logistic Regression on host-only URLs.
- `reports/host_only_roc_curves.png`: Receiver Operating Characteristic curves for host-only evaluation.
- `reports/host_only_confusion_matrix.png`: Confusion matrix heatmaps for host-only models.
- `reports/host_only_feature_importance.png`: Bar chart of top 10 features by Gini importance for the host-only Random Forest.
- `reports/full_url_model_comparison.png`, `reports/full_url_roc_curves.png`, `reports/full_url_confusion_matrix.png`, `reports/full_url_feature_importance.png`: Figures for the full-URL baseline demonstrating path-leakage bias.
- `reports/model_comparison.png`, `reports/roc_curves.png`, `reports/confusion_matrix.png`, `reports/feature_importance.png`: Primary deployed run plots.

### Application Screenshots (`docs/screenshots/`)
- `docs/screenshots/01_home.png`: Landing UI with input field, scan CTA, and glassmorphism styling.
- `docs/screenshots/02_result_legit.png`: Result page for whitelisted legitimate site (`https://google.com`), confidence 99.99%, Low Risk.
- `docs/screenshots/03_result_legit_ml.png`: Result page for legitimate site evaluated via ML (`https://www.python.org`).
- `docs/screenshots/04_result_phishing.png`: Result page for phishing domain (`http://secure-paypal-login.xyz/verify`).
- `docs/screenshots/05_reasons.png`: Detail view showing rule-based risk audit heuristics with clear actionable explanations.
