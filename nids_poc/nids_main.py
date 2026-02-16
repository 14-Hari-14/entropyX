import sys
import time
import math
import os
import pefile
import pandas as pd
import joblib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add src to path to import extractor
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from extractor import extract_all_features

# --- CONFIGURATION ---
WATCH_DIR = "/dev/shm/suricata_data/filestore"
MODEL_PATH = "/home/hari/Computer_Science/projects/entropyX/Model/v1_scaled/malware_rf_v1_20260211.joblib"
SCALER_PATH = "/home/hari/Computer_Science/projects/entropyX/Model/v1_scaled/scaler_v1_20260211.joblib"

class MalwareAnalyzer(FileSystemEventHandler):
    def __init__(self):
        # Load Model and Scaler at startup
        print("[*] Loading Model and Scaler...")
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            print(f"[!] ERROR: Model or Scaler file not found at {MODEL_PATH} or {SCALER_PATH}")
            print("[!] Exiting...")
            sys.exit(1)
            
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        print("[+] Model Loaded Successfully.")

    def on_created(self, event):
        """Triggered whenever a file is added to the folder."""
        if event.is_directory:
            return

        print(f"\n[+] New File Detected: {event.src_path}")
        
        # Give the OS a tiny moment to finish writing the file
        time.sleep(0.5)
        self.analyze_file(event.src_path)

    def analyze_file(self, filepath):
        """Step 1: The 'Brain' Analysis using ML Model"""
        try:
            print(f"    |-- Extracting Features...")
            # Feature Extraction
            raw_features = extract_all_features(filepath)
            
            if not raw_features:
                print("    |-- [!] Error: Extraction failed or not a valid PE file")
                return

            # Convert to DataFrame for feature name consistency
            df_features = pd.DataFrame([raw_features])
            
            # Dropping columns that were dropped by trainer.py
            to_drop = ['filename', 'raw_size', 'virtual_size', 'family', 'is_malicious']
            X_input = df_features.drop(columns=[col for col in to_drop if col in df_features.columns])
            
            # Scale features
            try:
                X_scaled_array = self.scaler.transform(X_input)
            except ValueError as e:
                print(f"    |-- [!] Scaling Error: {e}")
                return

            # Inference
            prediction = self.model.predict(X_scaled_array)[0]
            probabilities = self.model.predict_proba(X_scaled_array)[0]
            conf_score = max(probabilities) * 100
            
            status = "MALICIOUS" if prediction == 1 else "BENIGN"
            
            # Output Result
            print(f"    |-- Verdict:    {status}")
            print(f"    |-- Confidence: {conf_score:.2f}%")
            
            if prediction == 1:
                print(f"    |-- [!!!] ALERT: MALWARE DETECTED via Random Forest Model")
                
                # Feature Impact Analysis (Optional but helpful)
                importances = self.model.feature_importances_
                feature_names = X_input.columns
                scaled_values = X_scaled_array[0]
                
                impact_scores = {}
                for name, weight, val in zip(feature_names, importances, scaled_values):
                    impact_scores[name] = abs(weight * val)

                sorted_impact = sorted(impact_scores.items(), key=lambda x: x[1], reverse=True)
                
                print(f"    |-- Top Risk Inidicators:")
                for i, (feat, score) in enumerate(sorted_impact[:3]):
                    print(f"        {i+1}. {feat:<20} (Impact: {score:.4f})")

        except Exception as e:
            print(f"    |-- Error analyzing file: {e}")
            import traceback
            traceback.print_exc() 

    def calculate_entropy(self, data):
        """Math: Sum(p(x) * log2(p(x)))"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        total_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            p = count / total_len
            entropy -= p * math.log2(p)
            
        return entropy

if __name__ == "__main__":
    print(f"[*] NIDS Intelligence Layer Running...")
    
    # Check if model files exist before starting watcher loop
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
       print(f"[!] ERROR: configured paths")
       print(f"    Model: {MODEL_PATH}")
       print(f"    Scaler: {SCALER_PATH}")
       print("    Please ensure paths are correct or run training script.")
       sys.exit(1)

    print(f"[*] Watching: {WATCH_DIR}")
    
    # Setup the recursive watcher
    observer = Observer()
    # Initialize the analyzer which loads the model
    event_handler = MalwareAnalyzer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()