import numpy as np
import lightgbm as lgb
import os

# 1. Load SOREL Features (Memory Mapped)
print("[*] Mapping features and labels...")
data = np.load('validation-features.npz', mmap_mode='r')
X = data['arr_0'] # Features (N, 2381)
y = data['arr_1'] # Labels (N,)

# 2. Slice a balanced subset (100k samples total)
print("[*] Selecting balanced samples...")
# Since validation set is mostly malware, we find the first 50k of each
mal_idx = np.where(y == 1)[0][:50000]
ben_idx = np.where(y == 0)[0][:50000]

idx = np.concatenate([mal_idx, ben_idx])
np.random.shuffle(idx)

X_train = X[idx]
y_train = y[idx]

# 3. Fast Train with LightGBM
print(f"[*] Training on {len(idx)} samples...")
train_set = lgb.Dataset(X_train, label=y_train)

params = {
    'objective': 'binary',
    'metric': 'auc',
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.1,
    'verbose': -1,
    'n_jobs': -1 # Use all CPU cores
}

# 100 rounds is plenty for a 100k sample prototype
model = lgb.train(params, train_set, num_boost_round=100)

# 4. Save the Model
model.save_model('sorel_model_v1.txt')
print("[+] SUCCESS! Model saved as: sorel_model_v1.txt")
