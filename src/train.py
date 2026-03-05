'''
Training script for model
'''
# BASIC IMPORTS
import os
import numpy as np
import pandas as pd
import lightgbm as lgb
import glob # Used for finding all JSONL files in the data directory
import gc # Garbage collection to manage memory during training

# SKLEARN IMPORTS
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, accuracy_score, confusion_matrix

# LOCAL IMPORTS
from config import FEATURE_COLS, MODEL_PATH, SEED, IMPORT_DROPOUT_RATE, RAW_COLS_NEEDED, MODEL_OUT
from extractor_json import extract_row_features

DATA_DIR = "/kaggle/input/datasets/weiweip/ember2024/Win64_train"
np.random.seed(SEED) # For reproducibility

jsonl_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.jsonl")))
if not jsonl_files:
    raise FileNotFoundError(f"No JSONL file in the directory: {DATA_DIR}")

processed_chunks = []
# Read file in small chunks -> extract data -> free memory -> repeat, prevents OOM errors
for file_path in jsonl_files:
    print(f"Processing file: {file_path}...")
    shard = pd.read_json(file_path, lines=True)
    shard = shard[[c for c in RAW_COLS_NEEDED if c in shard.columns]] # Keep only needed raw columns
    shard = shard[shard['label'].isin([0, 1])] # Filter out unlabeled data (label == -1)
    
    # apply feature extraction to shard and expand dicts into columns and add label back into the resulting dataframe
    rows = shard.apply(extract_row_features, axis=1, result_type="expand")
    rows["label"] = shard["label"].values
    
    # delete shard and run garabage collection to free memory before next iteration
    del shard
    gc.collect()
    
    # converts numbers to float32 to save memory and prevent crash
    for col in rows.columns:
        rows[col] = pd.to_numeric(rows[col], errors="coerce").astype(np.float32)

    processed_chunks.append(rows)

# Concatenate all processed chunks into a single DataFrame for training
df = pd.concat(processed_chunks, ignore_index=True)
del processed_chunks
gc.collect()

# SIMULATING 1MB TRUNCATION BY DROPPING IMPORTS AND EXPORTS
print("Simulating gateway truncation (Dropout)...")
imp_drop = np.random.rand(len(df)) < IMPORT_DROPOUT_RATE
df.loc[imp_drop, ["imp_available", "imp_dll_count", "imp_func_count", "imp_has_gui_libs", "imp_has_crt"]] = 0

exp_drop = np.random.rand(len(df)) < IMPORT_DROPOUT_RATE
df.loc[exp_drop, ["exp_available", "exp_count"]] = 0


# BUILD FEATURE MATRIX
# Keep only columns that actually exist (safety net)
feat_cols = [c for c in FEATURE_COLS if c in df.columns]

X = df[feat_cols].values    # already float32 from the downcast above
y = df["label"].values

# Free the DataFrame 
del df
gc.collect()

print(f"[*] Feature matrix: {X.shape[0]:,} samples × {X.shape[1]} features")
print(f"[*] Class balance: {(y == 1).sum():,} malware / {(y == 0).sum():,} benign")


# ─── 4. TRAIN / VAL SPLIT ───────────────────────────────────────────────────
X_train, X_val, y_train, y_val = train_test_split(
    X, y, test_size=0.15, stratify=y, random_state=SEED
)
del X, y
gc.collect()

train_set = lgb.Dataset(X_train, label=y_train, feature_name=feat_cols, free_raw_data=True)
val_set   = lgb.Dataset(X_val,   label=y_val,   reference=train_set, free_raw_data=True)

# TRAIN MODEL
# Monotone constraints: imp_available and exp_available should only
# INCREASE the malware score when set to 0 (missing data = more suspicious
# is fine, but "has imports → definitely malware" is nonsensical).
monotone = [0] * len(feat_cols)
for feat, direction in [
    ("imp_available", -1),   # missing imports → more suspicious, never less
    ("exp_available", -1),   # missing exports → more suspicious
    ("dd_cert_present", -1), # code-signed → less suspicious, never more
    ("imp_has_crt", -1),     # has C runtime → less suspicious (normal app)
]:
    if feat in feat_cols:
        monotone[feat_cols.index(feat)] = direction

params = {
    "objective": "binary",
    "metric": ["auc", "binary_logloss"],
    "boosting_type": "gbdt",
    "num_leaves": 64,
    "learning_rate": 0.05,
    "feature_fraction": 0.9,
    "bagging_fraction": 0.9,
    "bagging_freq": 1,
    "min_data_in_leaf": 100,
    "lambda_l2": 1.0,
    "monotone_constraints": monotone,
    "verbose": -1,
    "n_jobs": -1,
    "seed": SEED,
}

callbacks = [
    lgb.early_stopping(stopping_rounds=30),
    lgb.log_evaluation(period=25),
]

print("\n[*] Training LightGBM ...")
model = lgb.train(
    params,
    train_set,
    num_boost_round=500,
    valid_sets=[train_set, val_set],
    valid_names=["train", "val"],
    callbacks=callbacks,
)

# EVALUATE
y_val_prob = model.predict(X_val)
auc = roc_auc_score(y_val, y_val_prob)

for thresh in [0.5, 0.4, 0.3, 0.2, 0.1]:
    y_pred = (y_val_prob >= thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred, labels=[0, 1]).ravel()
    acc    = accuracy_score(y_val, y_pred)
    recall = tp / (tp + fn) if (tp + fn) else 0
    fpr    = fp / (fp + tn) if (fp + tn) else 0
    print(f"  thresh={thresh:.1f}  acc={acc:.4f}  recall={recall:.4f}  FPR={fpr:.4f}  TP={tp} FN={fn} FP={fp}")

print(f"\n[*] Validation AUC: {auc:.5f}")

# FEATURE IMPORTANCE
imp = model.feature_importance(importance_type="gain")
feat_imp = sorted(zip(feat_cols, imp), key=lambda x: x[1], reverse=True)
print("\n── Feature importance (gain) ──")
for name, score in feat_imp[:15]:
    print(f"  {name:<28s} {score:>12.1f}")

# SAVE MODEL
model.save_model(MODEL_OUT)
print(f"\n[+] Model saved → {MODEL_OUT}")
print(f"    Features: {len(feat_cols)}")
print(f"    Best iteration: {model.best_iteration}")