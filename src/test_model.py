import joblib
import pandas as pd
import os
import numpy as np
import sys

# --- CONFIGURATION SWITCH ---
# Set this to "v3" or "v4" to switch modes
MODEL_VERSION = "v4" 

# IMPORTS BASED ON VERSION
if MODEL_VERSION == "v3":
    from extractor import extract_all_features
else:
    from ember.ember_extractor import PEFeatureExtractor

def generate_ember_columns():
    """ 
    Helper to generate column names for EMBER v4 so Feature Importance works 
    (Same logic as builder script)
    """
    headers = []
    # 1. ByteHistogram (256)
    headers.extend([f"byte_hist_{i}" for i in range(256)])
    # 2. ByteEntropyHistogram (256)
    headers.extend([f"byte_entropy_{i}" for i in range(256)])
    # 3. StringExtractor (104)
    headers.extend(["strings_num", "strings_avgl", "strings_printables"])
    headers.extend([f"strings_printabledist_{i}" for i in range(96)])
    headers.extend(["strings_entropy", "strings_paths", "strings_urls", "strings_registry", "strings_MZ"])
    # 4. GeneralFileInfo (10)
    headers.extend(["gen_size", "gen_vsize", "gen_has_debug", "gen_exports", "gen_imports", 
                    "gen_has_relocations", "gen_has_resources", "gen_has_signature", "gen_has_tls", "gen_symbols"])
    # 5. HeaderFileInfo (62)
    headers.append("header_timestamp")
    headers.extend([f"header_machine_hash_{i}" for i in range(10)])
    headers.extend([f"header_char_hash_{i}" for i in range(10)])
    headers.extend([f"header_subsys_hash_{i}" for i in range(10)])
    headers.extend([f"header_dllchar_hash_{i}" for i in range(10)])
    headers.extend([f"header_magic_hash_{i}" for i in range(10)])
    headers.extend(["header_img_ver_maj", "header_img_ver_min", "header_lnk_ver_maj", "header_lnk_ver_min",
                    "header_os_ver_maj", "header_os_ver_min", "header_sub_ver_maj", "header_sub_ver_min",
                    "header_code_size", "header_hdr_size", "header_heap_commit"])
    # 6. SectionInfo (255)
    headers.extend(["sect_num", "sect_zero_size", "sect_empty_name", "sect_rx", "sect_w"])
    headers.extend([f"sect_size_hash_{i}" for i in range(50)])
    headers.extend([f"sect_entropy_hash_{i}" for i in range(50)])
    headers.extend([f"sect_vsize_hash_{i}" for i in range(50)])
    headers.extend([f"sect_entry_hash_{i}" for i in range(50)])
    headers.extend([f"sect_char_hash_{i}" for i in range(50)])
    # 7. ImportsInfo (1280)
    headers.extend([f"import_lib_hash_{i}" for i in range(256)])
    headers.extend([f"import_func_hash_{i}" for i in range(1024)])
    # 8. ExportsInfo (128)
    headers.extend([f"export_hash_{i}" for i in range(128)])
    # 9. DataDirectories (30)
    dd_names = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "CERTIFICATE", "RELOCATION", "DEBUG", "ARCH", 
                "GLOBAL_PTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"]
    for name in dd_names:
        headers.extend([f"dd_{name}_size", f"dd_{name}_rva"])
    return headers

def predict_file(file_path, model_path, scaler_path, version="v4"):
    X_input = None
    
    # ==========================================
    # BLOCK 1: V4 EXTRACTION (EMBER)
    # ==========================================
    if version == "v4":
        try:
            extractor = PEFeatureExtractor(feature_version=2)
            with open(file_path, 'rb') as f:
                bytez = f.read()
            
            # Extract Vector (returns numpy array)
            vector = extractor.feature_vector(bytez)
            
            # Convert to DataFrame with correct names
            cols = generate_ember_columns()
            X_input = pd.DataFrame([vector], columns=cols)
            
        except Exception as e:
            return f"ERROR (V4 Extraction): {e}", None, None

    # ==========================================
    # BLOCK 2: V3 EXTRACTION (MANUAL)
    # ==========================================
    elif version == "v3":
        try:
            # Extract Dictionary
            raw_features = extract_all_features(file_path)
            if not raw_features:
                return "ERROR: Extraction failed (V3)", None, None
            
            df_features = pd.DataFrame([raw_features])
            
            # Drop metadata columns to match training shape
            # Uncomment/Comment these based on your V3 training logic
            to_drop = [
                'filename', 
                'family', 
                'is_malicious', 
                'raw_size',       # Often dropped in V3
                'virtual_size'    # Often dropped in V3
            ]
            X_input = df_features.drop(columns=[col for col in to_drop if col in df_features.columns])
            
        except Exception as e:
            return f"ERROR (V3 Extraction): {e}", None, None

    # ==========================================
    # SHARED INFERENCE LOGIC
    # ==========================================
    
    # Load Model and Scaler
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        return f"ERROR: Model/Scaler not found at {model_path}", None, None
        
    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        
        # Scale
        X_scaled_array = scaler.transform(X_input)
        
        # Predict
        prediction = model.predict(X_scaled_array)
        probabilities = model.predict_proba(X_scaled_array)
        
        # Feature Impact Analysis
        # Get feature names from DataFrame
        feature_names = X_input.columns
        
        # Get Importance from model
        importances = model.feature_importances_
        
        # Get specific values for this file
        scaled_values = X_scaled_array[0]
        
        impact_scores = {}
        for name, weight, val in zip(feature_names, importances, scaled_values):
            # Impact = How much the model cares (weight) * How extreme this file's value is (val)
            impact_scores[name] = abs(weight * val)

        sorted_impact = sorted(impact_scores.items(), key=lambda x: x[1], reverse=True)
        
        return prediction[0], probabilities[0], sorted_impact

    except Exception as e:
        return f"ERROR (Inference): {e}", None, None

if __name__ == "__main__":
    # --- PATH CONFIGURATION ---
    
    # The Target File
    # target = "/home/hari/encoded_threat.exe"
    target = "/home/hari/Downloads/xdr-hids-client-1.9.4(2).exe"

    # The Model Paths (Comment/Uncomment based on usage)
    if MODEL_VERSION == "v4":
        # EMBER V4 PATHS
        model_file = "../Model/v4_ember/malware_rf_v4_20260218.joblib"
        scaler_file = "../Model/v4_ember/scaler_v4_20260218.joblib"
    else:
        # MANUAL V3 PATHS
        model_file = "../Model/v3_xgb/malware_xgb_v3_20260217.joblib"
        scaler_file = "../Model/v3_xgb/scaler_xgb_v3_20260217.joblib"
    
    # Run Prediction
    if os.path.exists(target):
        print(f"[*] Analyzing {os.path.basename(target)} using Model {MODEL_VERSION}...")
        
        verdict, confidence, impacts = predict_file(target, model_file, scaler_file, version=MODEL_VERSION)
        
        if isinstance(verdict, str) and "ERROR" in verdict:
            print(f"[!] {verdict}")
        else:
            status = "MALICIOUS" if verdict == 1 else "BENIGN"
            conf_score = max(confidence) * 100
            
            print(f"\n" + "="*50)
            print(f"       ENTROPY-X ({MODEL_VERSION.upper()}) REPORT")
            print(f"="*50)
            print(f"File:       {os.path.basename(target)}")
            print(f"Verdict:    {status}")
            print(f"Confidence: {conf_score:.2f}%")
            print(f"-"*50)
            
            print(f"Top 5 Drivers (Why?):")
            for i, (feat, score) in enumerate(impacts[:5]):
                print(f" {i+1}. {feat:<30} | Magnitude: {score:.4f}")
            print(f"="*50 + "\n")
    else:
        print(f"[!] File not found: {target}")