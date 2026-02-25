import pandas as pd
import os
import numpy as np
import lightgbm as lgb
from ember_extractor import PEFeatureExtractor

#  CONFIGURATION 
MODEL_PATH = "sorel_model_v1.txt" 
# TARGET_FILE = "/home/hari/Downloads/xdr-hids-client-1.9.4(2).exe"
# TARGET_FILE = "../../data/malicious/sgn/shikata_1.exe"
TARGET_FILE = "../../data/malicious/custom_malware_bash/custom_loader_1.exe"
# TARGET_FILE = r"C:\Users\whizhack\Desktop\HardBenign\BleachBit_5.0.2.3065_User_X86_nullsoft_en-US.exe"

def generate_ember_columns():
    """ 
    Standard EMBER v2 feature names (2381 features)
    """
    headers = []
    headers.extend([f"byte_hist_{i}" for i in range(256)])
    headers.extend([f"byte_entropy_{i}" for i in range(256)])
    headers.extend(["strings_num", "strings_avgl", "strings_printables"])
    headers.extend([f"strings_printabledist_{i}" for i in range(96)])
    headers.extend(["strings_entropy", "strings_paths", "strings_urls", "strings_registry", "strings_MZ"])
    headers.extend(["gen_size", "gen_vsize", "gen_has_debug", "gen_exports", "gen_imports", 
                    "gen_has_relocations", "gen_has_resources", "gen_has_signature", "gen_has_tls", "gen_symbols"])
    headers.append("header_timestamp")
    headers.extend([f"header_machine_hash_{i}" for i in range(10)])
    headers.extend([f"header_char_hash_{i}" for i in range(10)])
    headers.extend([f"header_subsys_hash_{i}" for i in range(10)])
    headers.extend([f"header_dllchar_hash_{i}" for i in range(10)])
    headers.extend([f"header_magic_hash_{i}" for i in range(10)])
    headers.extend(["header_img_ver_maj", "header_img_ver_min", "header_lnk_ver_maj", "header_lnk_ver_min",
                    "header_os_ver_maj", "header_os_ver_min", "header_sub_ver_maj", "header_sub_ver_min",
                    "header_code_size", "header_hdr_size", "header_heap_commit"])
    headers.extend(["sect_num", "sect_zero_size", "sect_empty_name", "sect_rx", "sect_w"])
    headers.extend([f"sect_size_hash_{i}" for i in range(50)])
    headers.extend([f"sect_entropy_hash_{i}" for i in range(50)])
    headers.extend([f"sect_vsize_hash_{i}" for i in range(50)])
    headers.extend([f"sect_entry_hash_{i}" for i in range(50)])
    headers.extend([f"sect_char_hash_{i}" for i in range(50)])
    headers.extend([f"import_lib_hash_{i}" for i in range(256)])
    headers.extend([f"import_func_hash_{i}" for i in range(1024)])
    headers.extend([f"export_hash_{i}" for i in range(128)])
    dd_names = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "CERTIFICATE", "RELOCATION", "DEBUG", "ARCH", 
                "GLOBAL_PTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"]
    for name in dd_names:
        headers.extend([f"dd_{name}_size", f"dd_{name}_rva"])
    return headers

def predict_sorel(file_path, model_path):
    if not os.path.exists(model_path):
        return f"ERROR: Model not found at {model_path}", None, None

    try:
        # 1. Feature Extraction (EMBER V2)
        extractor = PEFeatureExtractor(feature_version=2)
        with open(file_path, 'rb') as f:
            bytez = f.read()
        vector = extractor.feature_vector(bytez)
        #print(vector)
        
        # 2. Load LightGBM Model from Text
        model = lgb.Booster(model_file=model_path)
        
        # 3. Inference
        # LightGBM predict returns a single probability [0, 1] for binary
        prob = model.predict([vector])[0]
        verdict = 1 if prob > 0.5 else 0
        
        # 4. Feature Impact (Feature Gain)
        # Note: LightGBM doesn't use scalers, so we use 'gain' importance
        feature_names = generate_ember_columns()
        importances = model.feature_importance(importance_type='gain')
        
        impact_scores = {}
        for name, imp, val in zip(feature_names, importances, vector):
            # For trees, we look at gain * the presence/value of the feature
            impact_scores[name] = abs(imp * val)

        sorted_impact = sorted(impact_scores.items(), key=lambda x: x[1], reverse=True)
        
        return verdict, prob, sorted_impact

    except Exception as e:
        return f"ERROR: {e}", None, None

if __name__ == "__main__":
    if os.path.exists(TARGET_FILE):
        print(f"[*] Analyzing {os.path.basename(TARGET_FILE)} using SOREL-Mini...")
        
        verdict, prob, impacts = predict_sorel(TARGET_FILE, MODEL_PATH)
        
        if isinstance(verdict, str) and "ERROR" in verdict:
            print(f"[!] {verdict}")
        else:
            status = "MALICIOUS" if verdict == 1 else "BENIGN"
            # In binary L-GBM, confidence is prob if Malicious, (1-prob) if Benign
            conf_score = prob if verdict == 1 else (1 - prob)
            
            print(f"\n" + "="*50)
            print(f"       SOREL-INFUSED REPORT")
            print(f"="*50)
            print(f"File:       {os.path.basename(TARGET_FILE)}")
            print(f"Verdict:    {status}")
            print(f"Confidence: {conf_score*100:.2f}%")
            print(f"-"*50)
            
            print(f"Top 5 Drivers (Feature Gain):")
            for i, (feat, score) in enumerate(impacts[:5]):
                # Normalize score for readability
                print(f" {i+1}. {feat:<30} | Magnitude: {score:.4f}")
            print(f"="*50 + "\n")
    else:
        print(f"[!] Target file not found: {TARGET_FILE}")
