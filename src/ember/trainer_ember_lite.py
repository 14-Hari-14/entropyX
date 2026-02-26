import numpy as np
import lightgbm as lgb
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import roc_auc_score, make_scorer
import gc

# Load data
print("Mapping features...")
data = np.load('validation-features.npz', mmap_mode='r')
X_raw = data['arr_0']
y_raw = data['arr_1']

# Define Lite Features (Header/Sections/Imports)
lite_indices = np.arange(616, 2381)
lite_indices = np.delete(lite_indices, np.where(lite_indices == 626)[0]) # Drop Timestamp

search_limit = 50000

# Create ONE index array and apply it to both X and y
print("Shuffling data")
idx = np.random.permutation(len(y_raw))[:search_limit]

# Using 50k samples to tune hyperparameters will be replaced by full dataset in later iterations
search_limit = 50000 
search_idx = idx[:search_limit]

X_search = X_raw[search_idx][:, lite_indices].astype(np.float32)
y_search = y_raw[search_idx].astype(np.float32)

del data
del X_raw
del y_raw
gc.collect()

print(f"Hyperparameter Search Subset: {X_search.shape}")


param_dist = {
    # Paper used 64.
    'num_leaves': [31, 64, 128], 
    'max_depth': [-1],
    
    # Paper used 0.1
    'learning_rate': [0.05, 0.1],
    'n_estimators': [500, 1000], # (num_iterations in paper)
    
    #Paper used 0.9. We test 0.8 to force redundancy (Rust protection).
    'feature_fraction': [0.8, 0.9], # feature sampling
    'bagging_fraction': [0.8, 0.9], # row sampling per frequency
    'bagging_freq': [1, 5], # reshuffle every 1 or 5 trees
    
    
    # 1.0 = Balanced Accuracy (Paper default)
    # 3.0 = High Recall (Paranoid Sentry)
    'scale_pos_weight': [1.0, 2.0, 3.0], 
    
    # REGULARIZATION: Keep paper defaults or slightly stronger
    'lambda_l1': [0, 0.1],
    'lambda_l2': [1.0], # Paper default
}

# Initialize Model 
lgb_classifier = lgb.LGBMClassifier(
    objective='binary', 
    boosting_type='gbdt',
    n_jobs=-1, # Use all CPU cores for training
    verbose=-1 # Suppress warning unless fatal
)

# Run Randomized Search 
print(" Starting RandomizedSearchCV...")
random_search = RandomizedSearchCV(
    estimator=lgb_classifier, 
    param_distributions=param_dist,
    n_iter=10, # 10 random combinations to try, increase for better tuning (but takes longer)
    scoring='roc_auc', # We care about AUC, not Accuracy
    cv=3,              # 3-Fold CV( cross-validation ) 
    verbose=2, # Show progress and results for each iteration
    random_state=42, # reproducing splits and results
    n_jobs=-1
)

random_search.fit(X_search, y_search)

#  Report Results 
print("\n" + "="*40)
print("      HYPERPARAMETER RESULTS")
print("="*40)
print(f"Best AUC Score: {random_search.best_score_:.4f}")
print("Best Parameters Found:")
for key, value in random_search.best_params_.items():
    print(f"  {key}: {value}")

# (Optional) Final Train on FULL Dataset 
# Now that we know the best params, we train on the full 2.5M rows
print("\n Retraining Final Model on FULL dataset with Best Params...")

# Reload full data (sorted by our shuffle index)
X_full = X_raw[idx][:, lite_indices]
y_full = y_raw[idx]

best_params = random_search.best_params_
# Ensure objective is set (RandomSearch wrapper handles it differently)
best_params['objective'] = 'binary'
best_params['metric'] = 'auc'

train_set = lgb.Dataset(X_full, label=y_full)

final_model = lgb.train(
    best_params, 
    train_set, 
    num_boost_round=best_params['n_estimators']
)

final_model.save_model('sorel_lite_tuned_v2.txt')
print("[+] Final Tuned Model Saved: sorel_lite_tuned_v2.txt")