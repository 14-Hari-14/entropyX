import os
import csv
from extractor import extract_all_features

# --- CONFIGURATION ---
MALICIOUS_PATH_AUTH = './data/malicious/authentic/'
OUTPUT_CSV = './data/dataset_ransomware.csv'

# Provided headers from Linux dataset
COLUMN_HEADERS = [
    'filename', 'total_file_size', 'avg_entropy', 'max_entropy', 'min_entropy', 
    'std_entropy', 'num_sections', 'size_of_headers', 'raw_size', 'virtual_size', 
    'virtual_size_ratio', 'family', 'is_malicious'
]

def build_dataset():
    print(f"[*] Features to be used: {COLUMN_HEADERS}")
    print("[*] Building Windows Ransomware Dataset...")
    
    with open(OUTPUT_CSV, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=COLUMN_HEADERS)
        writer.writeheader()
        
        # Process authentic folder recursively to catch all families
        process_authentic_root(MALICIOUS_PATH_AUTH, writer)
        
    print(f"\n[SUCCESS] Ransomware part saved to {OUTPUT_CSV}")

def process_authentic_root(root_path, writer):
    count = 0
    # Walk through each family subfolder (Akira, LockBit, etc.)
    for root, dirs, files in os.walk(root_path):
        # Determine family name from current directory name
        # If we are in the root, family is 'Authentic', otherwise it's the folder name
        current_family = os.path.basename(root)
        if current_family == 'authentic' or not current_family:
            continue

        for file in files:
            if not file.endswith(('.exe', '.dll')):
                continue
                
            full_path = os.path.join(root, file)
            features = extract_all_features(full_path)
            
            if features:
                # Add metadata
                features['filename'] = file
                features['family'] = current_family
                features['is_malicious'] = 1
                
                # Ensure we only write keys present in our header list
                filtered_features = {k: v for k, v in features.items() if k in COLUMN_HEADERS}
                writer.writerow(filtered_features)
                count += 1
                
                if count % 20 == 0:
                    print(f"    Processed {count} ransomware files...", end='\r')

    print(f"\n    Finished: {count} valid samples processed.")

if __name__ == "__main__":
    build_dataset()