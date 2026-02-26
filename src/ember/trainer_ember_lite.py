import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
import gc
import sys
import random

print("Loading data with memory mapping...")
data = np.load('validation-features.npz', mmap_mode='r')

X_raw = data['arr_0']
y_raw = data['arr_1']

lite_indices = np.arange(616, 2381)
lite_indices = np.delete(lite_indices, np.where(lite_indices == 626)[0])

print("Train/Test split (index-based, no copy)...")

indices = np.arange(len(y_raw))
train_idx, test_idx = train_test_split(
    indices,
    test_size=0.2,
    random_state=42
)

print("Selecting 300k subset for hyperparameter tuning...")
subset_size = min(300000, len(train_idx))
search_idx = np.random.choice(train_idx, subset_size, replace=False)

# Create LightGBM Dataset directly from memmap slice
X_search = X_raw[search_idx][:, lite_indices]
y_search = y_raw[search_idx]

train_data = lgb.Dataset(X_search, label=y_search, free_raw_data=True)

param_grid = [
    {"learning_rate": 0.1, "num_leaves": 64},
    {"learning_rate": 0.05, "num_leaves": 128},
    {"learning_rate": 0.05, "num_leaves": 64},
]

print("Running manual hyperparameter tuning...")

best_auc = 0
best_params = None

for params in param_grid:
    full_params = {
        "objective": "binary",
        "metric": "auc",
        "boosting_type": "gbdt",
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "min_data_in_leaf": 100,
        "lambda_l2": 1.0,
        "verbose": -1,
        **params
    }

    cv_result = lgb.cv(
    full_params,
    train_data,
    num_boost_round=1500,
    nfold=3,
    stratified=True,
    seed=42,
    callbacks=[
        lgb.early_stopping(stopping_rounds=50),
        lgb.log_evaluation(100)
    ]
    )

    auc_key = [k for k in cv_result.keys() if "auc-mean" in k][0]
    mean_auc = max(cv_result[auc_key])
    print(f"Params {params} → AUC: {mean_auc:.6f}")

    if mean_auc > best_auc:
        best_auc = mean_auc
        best_params = full_params

print("\n=============================")
print("BEST TUNING RESULT")
print("=============================")
print(f"AUC: {best_auc:.6f}")
print("Params:", best_params)
print("=============================\n")

del X_search, y_search, train_data
gc.collect()

print("Choose training configuration:")
print("1 → Use tuned hyperparameters")
print("2 → Use SOREL baseline parameters")
print("0 → Abort")

choice = input("Enter your choice: ")

if choice == "1":
    final_params = best_params
elif choice == "2":
    final_params = {
        "objective": "binary",
        "metric": "auc",
        "boosting_type": "gbdt",
        "learning_rate": 0.1,
        "num_leaves": 64,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "min_data_in_leaf": 100,
        "lambda_l2": 1.0,
        "verbose": -1
    }
else:
    sys.exit()

print("Preparing full dataset (no NumPy slicing)...")

# Slice only lite features ONCE (still memmap view)
X_lite = X_raw[:, lite_indices]
y_full = y_raw

# Create LightGBM Dataset from memmap view
full_dataset = lgb.Dataset(
    X_lite,
    label=y_full,
    free_raw_data=False
)

print("Training final model using internal validation split...")

final_model = lgb.train(
    final_params,
    full_dataset,
    num_boost_round=2000,
    valid_sets=[full_dataset],
    valid_names=["train"],
)

print("Saving model...")
final_model.save_model("sorel_lite_final_model.txt")

print("Training complete.")