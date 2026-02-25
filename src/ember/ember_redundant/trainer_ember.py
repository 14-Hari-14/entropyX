import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

# --- CONFIG ---
DATASET_FILE = '../data/dataset_ember_merged.csv'  
VERSION = "v4"

def train_v4():
    # Load Data
    print(f"[*] Loading {DATASET_FILE}...")
    df = pd.read_csv(DATASET_FILE)
    
    # Preprocessing
    drop_cols = ['is_malicious', 'family']
    X = df.drop(columns=drop_cols, errors='ignore')
    y = df['is_malicious']

    print(f"[*] Feature Matrix Shape: {X.shape}")
    
    # 3. Stratified Split (80/20)
    # We keep track of indices (idx_test) to identify survivors later
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Scaling
    # EMBER features vary wildly (byte counts vs entropy), so scaling is crucial
    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 5. Train Random Forest
    print("[*] Training Random Forest V4 (EMBER features)...")
    # n_jobs=-1 uses all CPU cores for training
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    # 6. Evaluate
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
    
    # 7. Feature Importance
    print("\n--- Feature Importance (Top 20) ---")
    importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
    print(importances.head(20))

    # 8. Survivor Analysis
    print("\n" + "="*40)
    print("   SURVIVOR ANALYSIS (False Negatives)")
    print("="*40)
    
    # We recover metadata using the indices we saved
    # Note: Filenames are NOT in the dataset, so we use Row ID
    test_meta = df.loc[idx_test, ['family']].copy()
    test_meta['actual'] = y_test
    test_meta['predicted'] = y_pred
    
    # Filter for False Negatives (Actual=1, Pred=0)
    survivors = test_meta[(test_meta['actual'] == 1) & (test_meta['predicted'] == 0)]
    
    if len(survivors) > 0:
        print(f"WARNING: The model missed {len(survivors)} malware samples:")
        for idx, row in survivors.iterrows():
            print(f" - CSV Row #{idx} (Family: {row['family']})")
            # We can't print entropy/sections easily unless we know the exact column names
            # because EMBER hashed them.
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
    train_v4()