import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

# --- CONFIG ---
DATASET_FILE = '../data/dataset_merged_v2.csv'  
VERSION = "v3"

def train_v3():
    # Load Data
    print(f"[*] Loading {DATASET_FILE}...")
    df = pd.read_csv(DATASET_FILE)
    
    # We keep 'filename' and 'family' in a separate dataframe for error analysis later
    # but drop them from the training set 'X'
    meta_cols = ['filename', 'family']
    X = df.drop(columns=['is_malicious', 'raw_size', 'virtual_size'] + meta_cols)
    y = df['is_malicious']
    
    # Stratified Split (80/20)
    # We split INDICES so we can track back to the filenames later
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    print("[*] Training Random Forest V3...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*40)
    print(f"   MODEL {VERSION} RESULTS")
    print("="*40)
    print(f"ACCURACY: {acc:.2%}")
    
    print("\n[CONFUSION MATRIX]")
    cm = confusion_matrix(y_test, y_pred)
    print(f"True Negatives (Benign):  {cm[0][0]}")
    print(f"False Positives (Alarm):  {cm[0][1]}")
    print(f"False Negatives (Missed): {cm[1][0]}  <-- THE SURVIVORS")
    print(f"True Positives (Caught):  {cm[1][1]}")
    
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
    test_meta = df.loc[idx_test, meta_cols].copy()
    test_meta['actual'] = y_test
    test_meta['predicted'] = y_pred
    
    # Filter for False Negatives (Actual=1, Pred=0)
    survivors = test_meta[(test_meta['actual'] == 1) & (test_meta['predicted'] == 0)]
    
    if len(survivors) > 0:
        print(f"WARNING: The model missed {len(survivors)} malware samples:")
        for idx, row in survivors.iterrows():
            # Get the features for this specific survivor to see WHY it was missed
            features = df.loc[idx, ['max_entropy', 'num_sections']]
            print(f" - {row['filename']} ({row['family']})")
            print(f"   Entropy: {features['max_entropy']:.4f}, Sections: {features['num_sections']}")
    else:
        print("PERFECT CATCH: No malware survived the test set!")

    # 9. Save Artifacts
    timestamp = datetime.now().strftime("%Y%m%d")
    model_filename = f"malware_rf_{VERSION}_{timestamp}.joblib"
    scaler_filename = f"scaler_{VERSION}_{timestamp}.joblib"
    
    joblib.dump(model, model_filename)
    joblib.dump(scaler, scaler_filename)
    print(f"\n[SUCCESS] Saved model to {model_filename}")

if __name__ == "__main__":
    train_v3()