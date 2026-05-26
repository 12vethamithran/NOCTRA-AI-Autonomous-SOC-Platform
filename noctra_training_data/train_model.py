"""
Train XGBoost classifier on training_corpus.ndjson.

Features extracted from each record (no heavy NLP — pure signal):
  - char-level stats on the raw line
  - structural signals (has IP, has user, has timestamp)
  - format one-hot
  - TF-IDF bag-of-words on raw (top 500 terms)

Outputs:
  backend/models/ml_detector.pkl   — trained XGBoost pipeline
  backend/models/ml_detector_meta.json — metrics + feature info
"""
import json, re, joblib, hashlib
from pathlib import Path
from collections import Counter

import numpy as np
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report
from scipy.sparse import hstack, csr_matrix
import xgboost as xgb

BASE   = Path(__file__).parent
CORPUS = BASE / "normalized" / "training_corpus.ndjson"
MODEL_DIR = BASE.parent / "backend" / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_OUT = MODEL_DIR / "ml_detector.pkl"
META_OUT  = MODEL_DIR / "ml_detector_meta.json"

IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RE = re.compile(r'(?:user|username|userName)["\s:=]+\S+', re.I)
TS_RE   = re.compile(r'\d{4}-\d{2}-\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}')

def handcrafted_features(raw: str) -> list[float]:
    """Return a fixed 12-dim float vector from the raw log line."""
    length = min(len(raw), 5000)
    digits = sum(c.isdigit() for c in raw)
    specials = sum(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?\\" for c in raw)
    upper = sum(c.isupper() for c in raw)
    spaces = raw.count(" ")
    ips = len(IP_RE.findall(raw))
    has_user = int(bool(USER_RE.search(raw)))
    has_ts   = int(bool(TS_RE.search(raw)))
    has_error = int(any(w in raw.lower() for w in ("fail", "error", "deny", "block", "invalid", "reject")))
    has_privesc = int(any(w in raw.lower() for w in ("admin", "root", "sudo", "privilege", "4732", "4720")))
    has_exfil = int(any(w in raw.lower() for w in ("upload", "exfil", "transfer", "copy", "outbound")))
    has_injection = int(any(w in raw.lower() for w in ("select", "union", "script", "eval", "exec", "cmd")))
    return [
        length / 5000,
        digits / max(length, 1),
        specials / max(length, 1),
        upper / max(length, 1),
        spaces / max(length, 1),
        min(ips, 5) / 5,
        has_user, has_ts, has_error, has_privesc, has_exfil, has_injection,
    ]

FORMAT_LIST = ["syslog", "json", "waf", "csv", "zeek", "evtx", "generic"]

def format_features(fmt: str) -> list[float]:
    return [1.0 if fmt == f else 0.0 for f in FORMAT_LIST]

print("━"*60)
print("  TRAINING — loading corpus …")
print("━"*60)

raws, labels, hand_feats, fmt_feats = [], [], [], []

with open(CORPUS, encoding="utf-8") as fh:
    for line in fh:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        raw = str(rec.get("raw") or "")
        if not raw.strip():
            continue
        label = 1 if rec.get("label") == "attack" else 0
        raws.append(raw[:1000])
        labels.append(label)
        hand_feats.append(handcrafted_features(raw))
        fmt_feats.append(format_features(rec.get("format") or "generic"))

print(f"  Loaded {len(raws):,} records ({sum(labels):,} attacks, {len(labels)-sum(labels):,} benign)")

y = np.array(labels, dtype=np.int32)

# ── Dense hand-crafted + format features (no leakage risk — purely stateless) ──
X_dense = np.array(
    [h + f for h, f in zip(hand_feats, fmt_feats)], dtype=np.float32
)

# ── Feature matrix for final model (TF-IDF fitted on full corpus — intentional
#    for the saved production bundle; CV below uses a Pipeline to avoid leakage) ──
print("  Building TF-IDF features …")
tfidf = TfidfVectorizer(
    max_features=500,
    analyzer="word",
    token_pattern=r"[A-Za-z0-9_\-\.]{2,}",
    ngram_range=(1, 2),
    sublinear_tf=True,
)
X_tfidf = tfidf.fit_transform(raws)
X       = hstack([X_tfidf, csr_matrix(X_dense)])

print(f"  Feature matrix: {X.shape[0]:,} × {X.shape[1]} ")

# ── Train XGBoost (production model) ────────────────────────────────────────
print("  Training XGBoost …")
scale_pos_weight = (y == 0).sum() / max((y == 1).sum(), 1)

clf = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=1,
    verbosity=0,
)
clf.fit(X, y)

# ── Cross-val AUC — use Pipeline so TF-IDF is re-fitted inside each fold ────
# This avoids the leakage where the TF-IDF vocabulary seen the holdout set.
print("  Cross-validating (5-fold AUC, Pipeline-safe) …")

class _DenseAppender(BaseEstimator, TransformerMixin):
    """Append pre-computed dense features to TF-IDF sparse output per fold."""
    def __init__(self, dense): self.dense = dense
    def fit(self, idx, y=None): return self
    def transform(self, idx):
        return csr_matrix(self.dense[idx])

# CV pipeline operates on row indices so we can attach dense features per fold
row_idx = np.arange(len(raws))

cv_tfidf = TfidfVectorizer(
    max_features=500, analyzer="word",
    token_pattern=r"[A-Za-z0-9_\-\.]{2,}",
    ngram_range=(1, 2), sublinear_tf=True,
)
cv_clf = xgb.XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=1, verbosity=0,
)
raws_arr = np.array(raws, dtype=object)

cv_auc_scores = []
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
for train_idx, test_idx in cv.split(row_idx, y):
    cv_tfidf_fold = TfidfVectorizer(
        max_features=500, analyzer="word",
        token_pattern=r"[A-Za-z0-9_\-\.]{2,}",
        ngram_range=(1, 2), sublinear_tf=True,
    )
    X_tr = hstack([cv_tfidf_fold.fit_transform(raws_arr[train_idx]), csr_matrix(X_dense[train_idx])])
    X_te = hstack([cv_tfidf_fold.transform(raws_arr[test_idx]),      csr_matrix(X_dense[test_idx])])
    fold_clf = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        use_label_encoder=False, eval_metric="logloss",
        random_state=42, n_jobs=1, verbosity=0,
    )
    fold_clf.fit(X_tr, y[train_idx])
    from sklearn.metrics import roc_auc_score
    probs = fold_clf.predict_proba(X_te)[:, 1]
    cv_auc_scores.append(roc_auc_score(y[test_idx], probs))

auc_scores = np.array(cv_auc_scores)
print(f"  AUC: {auc_scores.mean():.4f} ± {auc_scores.std():.4f}")

# Full-set report
y_pred = clf.predict(X)
report = classification_report(y, y_pred, target_names=["benign", "attack"])
print(report)

# ── Save ────────────────────────────────────────────────────────────────────
bundle = {"tfidf": tfidf, "clf": clf}
joblib.dump(bundle, MODEL_OUT, compress=3)
print(f"  ✓ Model saved → {MODEL_OUT}")

META_OUT.write_text(json.dumps({
    "trained_at": __import__("datetime").datetime.utcnow().isoformat(),
    "corpus_records": len(raws),
    "attack_records": int(sum(labels)),
    "benign_records": int(len(labels) - sum(labels)),
    "feature_dim": X.shape[1],
    "tfidf_vocab_size": len(tfidf.vocabulary_),
    "cv_auc_mean": round(float(auc_scores.mean()), 4),
    "cv_auc_std":  round(float(auc_scores.std()), 4),
    "model": "XGBClassifier",
    "n_estimators": 300,
    "format_features": FORMAT_LIST,
    "handcrafted_dim": 12,
}, indent=2), encoding="utf-8")
print(f"  ✓ Meta  saved → {META_OUT}")
