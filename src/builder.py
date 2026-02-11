import os
import csv
# Import the function from your extractor file
from extractor import extract_all_features

# Configuration
BENIGN_PATH = '../data/benign/'
MALICIOUS_PATH_SGN = '../data/malicious/sgn/'
MALICIOUS_PATH_CUSTOM = '../data/malicious/custom_malware_bash/'
OUTPUT_CSV = '../data/dataset_v1.csv'

def build_dataset():
    # We grab a known good file to detect the feature names
    header_file = os.path.join(MALICIOUS_PATH_SGN, "shikata_1.exe")
    
    if not os.path.exists(header_file):
        print(f"Error: Sample file not found at {header_file}")
        return

    # Extract once to get the dictionary keys
    sample_data = extract_all_features(header_file)
    if not sample_data:
        print("Error: Could not extract features from sample.")
        return

    # Prepare CSV Headers
    column_headers = list(sample_data.keys())
    column_headers.append("family")
    column_headers.append('is_malicious')
    print(f"Features detected: {column_headers}")

    # 2. Streaming Build Process
    print("Building dataset...")
    
    with open(OUTPUT_CSV, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=column_headers)
        writer.writeheader()
        
        # Helper to process a folder
        # We pass the 'writer' object to it so it can write directly to the open file
        process_folder(BENIGN_PATH, "benign", 0, writer)
        process_folder(MALICIOUS_PATH_CUSTOM, "custom",1, writer)
        process_folder(MALICIOUS_PATH_SGN, "sgn",1, writer)
        
    print(f"\nSuccess! Dataset saved to {OUTPUT_CSV}")

def process_folder(folder_path, family, label, writer):
    count = 0
    # os.walk yields (root, dirs, files) - we only need root and files
    for root, _, files in os.walk(folder_path):
        for file in files:
            # Defensive Check: Ignore non-PE files (.DS_Store, .txt, .sh, etc.)
            if not file.endswith(('.exe', '.dll')):
                continue
                
            full_path = os.path.join(root, file)
            
            # Extract
            features = extract_all_features(full_path)
            
            # Write immediately (Streaming)
            if features:
                features['family'] = family
                features['is_malicious'] = label
                writer.writerow(features)
                count += 1
                
                # Update progress every 50 files
                if count % 50 == 0:
                    print(f"    Processed {count} files in {os.path.basename(folder_path)}...", end='\r')

    print(f"    Finished {folder_path}: {count} valid files processed.")

if __name__ == "__main__":
    build_dataset()