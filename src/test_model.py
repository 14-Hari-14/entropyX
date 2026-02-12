import joblib
import pandas as pd
import os
import numpy as np
from extractor import extract_all_features

def predict_file(file_path, model_path, scaler_path):
    # Feature Extraction
    raw_features = extract_all_features(file_path)
    if not raw_features:
        return "ERROR: Not a valid PE file or extraction failed", None, None

    # Convert to DataFrame for feature name consistency
    df_features = pd.DataFrame([raw_features])
    
    # Dropping columns that were dropped by trainer.py
    to_drop = ['filename', 'raw_size', 'virtual_size', 'family', 'is_malicious']
    X_input = df_features.drop(columns=[col for col in to_drop if col in df_features.columns])

    # Load Model and Scaler
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        return "ERROR: Model or Scaler file not found", None, None
        
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    
    # Using the scaler trained on your 1000+ samples
    X_scaled_array = scaler.transform(X_input)
    X_scaled_df = pd.DataFrame(X_scaled_array, columns=X_input.columns)
    
    # Inference
    prediction = model.predict(X_scaled_array)
    probabilities = model.predict_proba(X_scaled_array)
    
    # Feature Impact Analysis
    importances = model.feature_importances_
    feature_names = X_input.columns
    scaled_values = X_scaled_array[0]
    
    # We calculate the impact by looking at the magnitude of (Importance * Scaled Value)
    impact_scores = {}
    for name, weight, val in zip(feature_names, importances, scaled_values):
        # We use absolute value to find the strongest drivers (positive or negative)
        impact_scores[name] = abs(weight * val)

    # Sort by impact
    sorted_impact = sorted(impact_scores.items(), key=lambda x: x[1], reverse=True)
    
    return prediction[0], probabilities[0], sorted_impact

if __name__ == "__main__":
    # --- PATH CONFIGURATION ---
    # target = "/home/hari/encoded_threat.exe"
    # target = "../data/benign/4545ffe2-0dc4-4df4-9d02-299ef204635e_hvsocket.dll"
    target = "/home/hari/Downloads/xdr-hids-client-1.9.4(2).exe"
    #target = "/home/hari/Computer_Science/projects/trace/temp_store/threat_update.exe"
    
    model_file = "/home/hari/Computer_Science/projects/entropyX/Model/v1_scaled/malware_rf_v1_20260211.joblib"
    scaler_file = "/home/hari/Computer_Science/projects/entropyX/Model/v1_scaled/scaler_v1_20260211.joblib"
    
    if os.path.exists(target):
        verdict, confidence, impacts = predict_file(target, model_file, scaler_file)
        
        if isinstance(verdict, str) and "ERROR" in verdict:
            print(f"[!] {verdict}")
        else:
            status = "MALICIOUS" if verdict == 1 else "BENIGN"
            conf_score = max(confidence) * 100
            
            print(f"\n" + "="*50)
            print(f"       ENTROPY-X CLASSIFICATION REPORT")
            print(f"="*50)
            print(f"File:       {os.path.basename(target)}")
            print(f"Verdict:    {status}")
            print(f"Confidence: {conf_score:.2f}%")
            print(f"-"*50)
            
            print(f"Top 5 Drivers (Scaled Impact):")
            for i, (feat, score) in enumerate(impacts[:5]):
                print(f" {i+1}. {feat:<20} | Magnitude: {score:.4f}")
            print(f"="*50 + "\n")
    else:
        print(f"[!] File not found: {target}")