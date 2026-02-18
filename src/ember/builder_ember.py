import os
import csv
import time
import concurrent.futures
from ember_extractor import PEFeatureExtractor

# --- CONFIGURATION ---
FOLDERS = {
    'benign': r'C:\Users\whizhack\Desktop\HardBenign',      
}
OUTPUT_CSV = 'dataset_benign_complete_3.csv'

# Uses 75% of cores to leave some juice for the OS (prevents freezing)
MAX_WORKERS = 2  # Safe mode for Windows VM

def generate_column_names():
    """
    Auto-generates meaningful column headers matching EMBER v2 features.
    Total: ~2381 columns.
    """
    headers = []
    
    # 1. ByteHistogram (256)
    headers.extend([f"byte_hist_{i}" for i in range(256)])
    
    # 2. ByteEntropyHistogram (256)
    headers.extend([f"byte_entropy_{i}" for i in range(256)])
    
    # 3. StringExtractor (104)
    # Order: numstrings, avlength, printables, printabledist(96), entropy, paths, urls, registry, MZ
    headers.extend(["strings_num", "strings_avgl", "strings_printables"])
    headers.extend([f"strings_printabledist_{i}" for i in range(96)])
    headers.extend(["strings_entropy", "strings_paths", "strings_urls", "strings_registry", "strings_MZ"])
    
    # 4. GeneralFileInfo (10)
    # Order: size, vsize, has_debug, exports, imports, has_relocations, has_resources, has_signature, has_tls, symbols
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

def process_file_wrapper(args):
    """
    Wrapper to handle the extraction in a separate process.
    """
    file_path, label_name, is_mal = args
    try:
        # Re-initialize inside the process to be safe
        extractor = PEFeatureExtractor(feature_version=2)
        with open(file_path, 'rb') as f:
            bytez = f.read()
        
        vector = extractor.feature_vector(bytez)
        row = vector.tolist()
        row.append(label_name)
        row.append(is_mal)
        return row
    except Exception as e:
        return None

def build_dataset_parallel():
    # 1. Safety Check
    if os.path.exists(OUTPUT_CSV):
        print(f"[!] WARNING: {OUTPUT_CSV} already exists.")
        print("    Please rename or delete it manually to avoid accidental data loss.")
        return

    # 2. Collect Files
    tasks = []
    print("[*] Scanning folders...")
    for label_name, folder_path in FOLDERS.items():
        if not os.path.exists(folder_path):
            print(f"[!] ERROR: Folder not found: {folder_path}")
            continue
            
        is_mal = 1 if label_name == 'malware' else 0
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                tasks.append((file_path, label_name, is_mal))
    
    total_files = len(tasks)
    print(f"[*] Found {total_files} files to process.")
    
    if total_files == 0:
        print("[!] No files found. Check your folder paths in the script!")
        return

    # 3. Setup CSV
    col_names = generate_column_names()
    col_names.append("family")
    col_names.append("is_malicious")

    # 4. Parallel Execution
    start_time = time.time()
    
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(col_names)
        
        print(f"[*] Starting parallel extraction with {MAX_WORKERS} workers...")
        
        # We use ProcessPoolExecutor for true parallelism
        with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Map returns results in the order they were submitted
            results = executor.map(process_file_wrapper, tasks)
            
            count = 0
            for row in results:
                if row:
                    writer.writerow(row)
                    count += 1
                
                if count % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = count / elapsed if elapsed > 0 else 0
                    print(f"    Processed {count}/{total_files} ({rate:.1f} files/sec)   ", end='\r')

    print(f"\n\n[SUCCESS] Dataset saved to {OUTPUT_CSV}")
    print(f"Total Time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    build_dataset_parallel()