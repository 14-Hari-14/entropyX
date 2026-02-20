import numpy as np
import lightgbm as lgb
import os

# --- 1. Define the Lite Features Mask ---
print("[*] Calculating Lite Feature Indices...")
# Features 616 through 2380 represent the headers, sections, imports, exports, and directories
lite_indices = np.arange(616, 2381) 
# Surgically remove index 626 (header_timestamp) to prevent concept drift
lite_indices = np.delete(lite_indices, np.where(lite_indices == 626)[0])

# --- 2. Load Data (Memory Mapped) ---
print("[*] Mapping features and labels to disk...")
data = np.load('validation-features.npz', mmap_mode='r')
X = data['arr_0'] # Shape: (Total_Rows, 2381) - Stays on disk
y = data['arr_1'] # Shape: (Total_Rows,)

# --- 3. Find Balanced Indices ---
print("[*] Selecting 100k balanced samples...")
mal_idx = np.where(y == 1)[0][:50000]
ben_idx = np.where(y == 0)[0][:50000]

idx = np.concatenate([mal_idx, ben_idx])
np.random.shuffle(idx)

# --- 4. The Memory-Safe Extraction ---
print("[*] Extracting Lite Features into RAM...")
# IMPORTANT: Slice the 100k rows FIRST to keep the RAM footprint tiny, 
# THEN slice out the 1,763 Lite columns from that small subset.
X_train = X[idx][:, lite_indices]
y_train = y[idx]

# --- 5. Fast Train with LightGBM ---
print(f"[*] Training on {len(idx)} samples with {X_train.shape[1]} features...")
train_set = lgb.Dataset(X_train, label=y_train)

params = {
    'objective': 'binary',
    'metric': 'auc',
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.1,
    'verbose': -1,
    'n_jobs': -1, # Use all CPU cores
    'scale_pos_weight': 3.0 # The Sentry Paranoia setting (penalize missed malware 3x more)
}

# 100 rounds for a quick prototype
model = lgb.train(params, train_set, num_boost_round=100)

# --- 6. Save the Model ---
model.save_model('sorel_lite_model_v1.txt')
print("[+] SUCCESS! Model saved as: sorel_lite_model_v1.txt")