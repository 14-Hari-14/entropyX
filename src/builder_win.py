import os
import csv
from extractor import extract_all_features

# --- CONFIGURATION ---
# Base paths - will be modified based on user input
BASE_PATH = r'C:\Users\whizhack\Desktop'
HEADERS = [
    'filename', 'total_file_size', 'avg_entropy', 'max_entropy', 'min_entropy', 
    'std_entropy', 'num_sections', 'size_of_headers', 'raw_size', 'virtual_size', 
    'virtual_size_ratio', 'family', 'is_malicious'
]

def build_dataset():
    print("Select dataset type to build:")
    print("1: Malicious")
    print("0: Benign")
    
    choice = input("Enter choice (1/0): ").strip()
    
    if choice == '1':
        is_malicious = 1
        label = "Malicious"
        target_folder = "Malware" # Assuming folder name, adjust if needed
        output_file = "dataset_malware.csv"
    elif choice == '0':
        is_malicious = 0
        label = "benign"
        target_folder = "HardBenign"
        output_file = "dataset_benign.csv"
    else:
        print("Invalid choice. Exiting.")
        return

    full_target_path = os.path.join(BASE_PATH, target_folder)
    full_output_path = os.path.join(BASE_PATH, target_folder, output_file)

    print(f"[*] Configuration: {label}")
    print(f"[*] Source: {full_target_path}")
    print(f"[*] Output: {full_output_path}")
    
    print(f"[*] Features to be used: {HEADERS}")
    print(f"[*] Building Windows {label} Dataset...")
    
    with open(full_output_path, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=HEADERS)
        writer.writeheader()
        
        # Process folder recursively
        if is_malicious == 1:
            process_malicious_root(full_target_path, writer)
        else:
            process_benign_root(full_target_path, writer)
        
    print(f"\n[SUCCESS] {label} data saved to {full_output_path}")

def process_malicious_root(root_path, writer):
    count = 0
    # Walk through each family subfolder
    for root, dirs, files in os.walk(root_path):
        current_family = os.path.basename(root)
        
        # Skip if we are in the base malware folder and not a family subfolder (optional check)
        # if root == root_path: continue 

        for file in files:
            if not file.endswith(('.exe', '.dll')):
                continue
                
            process_file(root, file, current_family, 1, writer)
            count += 1
            if count % 20 == 0:
                print(f"    Processed {count} malicious files...", end='\r')
    print(f"\n    Finished: {count} malicious samples processed.")

def process_benign_root(root_path, writer):
    count = 0
    # Walk through benign folders
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if not file.endswith(('.exe', '.dll')):
                continue
                
            process_file(root, file, "benign", 0, writer)
            count += 1
            if count % 20 == 0:
                print(f"    Processed {count} benign files...", end='\r')
    print(f"\n    Finished: {count} benign samples processed.")

def process_file(root, file, family, is_malicious, writer):
    full_path = os.path.join(root, file)
    try:
        features = extract_all_features(full_path)
        
        if features:
            # Add metadata
            features['filename'] = file
            features['family'] = family
            features['is_malicious'] = is_malicious
            
            # Ensure we only write keys present in our header list
            filtered_features = {k: v for k, v in features.items() if k in HEADERS}
            writer.writerow(filtered_features)
    except Exception as e:
        print(f"Error processing {file}: {e}")

if __name__ == "__main__":
    build_dataset()