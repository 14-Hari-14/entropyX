import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

# --- CONFIG ---
DATASET_FILE = '../data/dataset_merged_v2.csv'  
VERSION = "v3_xgb"

def train_v3_xgb():
    # Load Data
    print(f"[*] Loading {DATASET_FILE}...")
    try:
        df = pd.read_csv(DATASET_FILE)
    except FileNotFoundError:
        print(f"[!] Error: Dataset file not found at {DATASET_FILE}")
        return

    # We keep 'filename' and 'family' in a separate dataframe for error analysis later
    # but drop them from the training set 'X'
    meta_cols = ['filename', 'family']
    
    # Check if columns exist before dropping
    cols_to_drop = ['is_malicious', 'raw_size', 'virtual_size'] + meta_cols
    existing_cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    
    X = df.drop(columns=existing_cols_to_drop)
    y = df['is_malicious']
    
    # 3. Stratified Split (80/20)
    # We split INDICES so we can track back to the filenames later
    print("[*] Splitting data...")
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scaling
    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train XGBoost
    print("[*] Training XGBoost V3...")
    # Using default parameters for binary classification
    model = xgb.XGBClassifier(
        n_estimators=100,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    print("[*] Evaluating model...")
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*40)
    print(f"   XGBOOST MODEL {VERSION} RESULTS")
    print("="*40)
    print(f"ACCURACY: {acc:.2%}")
    
    print("\n[CONFUSION MATRIX]")
    cm = confusion_matrix(y_test, y_pred)
    # Handle case where confusion matrix might be 1x1 or 2x2 depending on test set
    if cm.shape == (2, 2):
        print(f"True Negatives (Benign):  {cm[0][0]}")
        print(f"False Positives (Alarm):  {cm[0][1]}")
        print(f"False Negatives (Missed): {cm[1][0]}  <-- THE SURVIVORS")
        print(f"True Positives (Caught):  {cm[1][1]}")
    else:
        print(cm)
    
    print("\n[CLASSIFICATION REPORT]")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Feature Importance
    print("\n--- Feature Importance ---")
    importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
    print(importances.head(10))

    # Which samples gave false negatives
    print("\n" + "="*40)
    print("   SURVIVOR ANALYSIS (False Negatives)")
    print("="*40)
    
    # Recover the metadata for the test set using the indices
    # Verify meta_cols exist first
    available_meta_cols = [col for col in meta_cols if col in df.columns]
    
    if available_meta_cols:
        test_meta = df.loc[idx_test].copy()
        test_meta['actual'] = y_test
        test_meta['predicted'] = y_pred
        
        # Filter for False Negatives (Actual=1, Pred=0)
        survivors = test_meta[(test_meta['actual'] == 1) & (test_meta['predicted'] == 0)]
        
        if len(survivors) > 0:
            print(f"WARNING: The model missed {len(survivors)} malware samples:")
            for idx, row in survivors.iterrows():
                # Get the features for this specific survivor to see WHY it was missed
                ent = row.get('max_entropy', 'N/A')
                sec = row.get('num_sections', 'N/A')
                fname = row.get('filename', 'Unknown')
                fam = row.get('family', 'Unknown')
                
                print(f" - {fname} ({fam})")
                
                ent_str = f"{ent:.4f}" if isinstance(ent, (int, float)) else ent
                print(f"   Entropy: {ent_str}, Sections: {sec}")
        else:
            print("PERFECT CATCH: No malware survived the test set!")
    else:
         print("Skipping survivor analysis (metadata columns missing)")

    # Save Artifacts
    timestamp = datetime.now().strftime("%Y%m%d")
    model_filename = f"malware_xgb_{VERSION}_{timestamp}.joblib"
    scaler_filename = f"scaler_xgb_{VERSION}_{timestamp}.joblib"
    
    
    joblib.dump(model, model_filename)
    joblib.dump(scaler, scaler_filename)
    print(f"\n[SUCCESS] Saved model to {model_filename}")

if __name__ == "__main__":
    train_v3_xgb()
