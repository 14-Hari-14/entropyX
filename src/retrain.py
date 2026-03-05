import pandas as pd
import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split
from config import FEATURE_COLS, SEED

# ─── 1. LOAD DATA ───────────────────────────────────────────────────────────
df = pd.read_csv("../data/test_real/dataset_ember_2024_merged_v2_labeled.csv")
feat_cols = [c for c in FEATURE_COLS if c in df.columns]

# Explicit downcast to float32 (fixes the missing code from your draft)
for col in feat_cols:
    df[col] = pd.to_numeric(df[col], errors='coerce').astype(np.float32)

X = df[feat_cols].values
y = df["label"].values

print(f"[*] Fine-Tuning matrix: {X.shape[0]:,} samples × {X.shape[1]} features")
print(f"[*] Class balance: {(y == 1).sum():,} malware / {(y == 0).sum():,} benign")

# ─── 2. THE 3-WAY IRONCLAD SPLIT ───────────────────────────────────────────
# Cut 1: Slice off 20% for the Vaulted Test Set (This is your final proof)
X_temp, X_vault, y_temp, y_vault = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=SEED
)

# Cut 2: Split the remaining 80% into Train (for trees) and Val (for early stopping)
# Setting test_size=0.20 here means 20% of the 80% (which is 16% of the total data)
X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.20, stratify=y_temp, random_state=SEED
)

# Free the temp variables
del X_temp, y_temp

print(f"[*] Training slice:   {X_train.shape[0]} files")
print(f"[*] Validation slice: {X_val.shape[0]} files (used for early stopping)")
print(f"[*] Vaulted Test:     {X_vault.shape[0]} files (saved to disk, completely unseen)")

# Save the Vaulted Test Set so evaluate.py can use it later
vault_df = pd.DataFrame(X_vault, columns=feat_cols)
vault_df['label'] = y_vault
VAULT_PATH = "../data/test_real/vaulted_test_set.csv"
vault_df.to_csv(VAULT_PATH, index=False)
print(f"[*] Vaulted Test Set saved to {VAULT_PATH}")

# ─── Create LightGBM Datasets ONLY for Train and Val ───
train_set = lgb.Dataset(X_train, label=y_train, feature_name=feat_cols, free_raw_data=True)
val_set   = lgb.Dataset(X_val, label=y_val, reference=train_set, free_raw_data=True)

# MONOTONE CONSTRAINTS
monotone = [0] * len(feat_cols)
for feat, direction in [
    ("imp_available", -1),
    ("exp_available", -1),
    ("dd_cert_present", -1),
    ("imp_has_crt", -1),
]:
    if feat in feat_cols:
        monotone[feat_cols.index(feat)] = direction

# PARAMS FOR FINE TUNING
BASE_MODEL_PATH = "../model/ember_lite_model_2024_v3.txt"

params = {
    'objective': 'binary',
    'metric': ['auc', 'binary_logloss'], # Actually track the performance
    'learning_rate': 0.01,               
    'lambda_l2': 1.0,
    'lambda_l1': 0.1,                    # Added from your tuned results
    'min_data_in_leaf': 50,              # Perfect regularization choice
    'num_leaves': 32,                    # Kept small to prevent memorization
    'feature_fraction': 0.8,             # Forces trees to look at different headers
    'monotone_constraints': monotone,    # MUST HAVE
    'seed': SEED
}

# FINE TUNING
print("\n[*] Initializing Residual Fine-Tuning via init_model...")
tuned_model = lgb.train(
    params,
    train_set,
    num_boost_round=100,                 # Bumping to 100 since LR is very low (0.01)
    valid_sets=[train_set, val_set],
    valid_names=["train", "val"],
    init_model=BASE_MODEL_PATH,          # THE CRITICAL FIX: Adds to existing trees
    callbacks=[
        lgb.early_stopping(stopping_rounds=20),
        lgb.log_evaluation(period=10)
    ]
)

# SAVE
SAVE_PATH = "../model/ember_tuned_2026.txt"
tuned_model.save_model(SAVE_PATH)
print(f"\n[+] Fine-tuning complete. Saved as {SAVE_PATH}")