import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

import joblib
from datetime import datetime

df = pd.read_csv('../data/dataset_merged.csv')

# Prepare Data
# Dropping based on your EDA findings (Multicollinearity)
X = df.drop(columns=['is_malicious', 'raw_size', 'virtual_size', 'filename', 'family']) 
y = df['is_malicious']

# Train Test Split (Stratified to maintain class balance)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))

print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred))

# 5. The Insight: Feature Importance
importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
print("\n--- Feature Importance (The 'Why') ---")
print(importances)

# 1. Create a versioned name
version = "v1"
timestamp = datetime.now().strftime("%Y%m%d")
model_filename = f"malware_rf_{version}_{timestamp}.joblib"
metadata_filename = f"metadata_{version}_{timestamp}.txt"

# 2. Save the model
joblib.dump(model, model_filename)

# 3. Save the Data Trail (Metadata)
# This is crucial for benchmarking later so you know what was in the training set
with open(metadata_filename, "w") as f:
    f.write(f"Model Version: {version}\n")
    f.write(f"Training Date: {datetime.now()}\n")
    f.write(f"Dataset: dataset_merged.csv\n")
    f.write(f"Samples: {len(df)} (Benign: 494, Malicious: 478)\n")
    f.write(f"Top Feature: {importances.index[0]} ({importances.iloc[0]:.4f})\n")

print(f"[SUCCESS] Model saved as {model_filename}")
print(f"[SUCCESS] Metadata saved as {metadata_filename}")