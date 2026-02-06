from collections import Counter
import math
import pefile
import numpy as np 
import os

def shanon_helper(binary_data) -> float:
    counter = Counter()
    entropy = 0.0
    
    counter.update(binary_data)
    total_bytes = sum(counter.values())
    
    # Safety check for empty files 
    if total_bytes == 0:
        return 0.0
    
    # Calculate the probability of each byte and use it to calculate entropy of the file
    for count in counter.values():
        prob = count/total_bytes
        entropy -= prob*math.log2(prob)
    
    # print(entropy)
    return entropy

# Avg entropy for malicious files is 1.41 because the file is padded with null data which reduces avg, therefore its necessary to look at it section wise
def get_entropy_features(pe) -> dict:
    pe_entropy_list  = []
    for section in pe.sections:
        section_data_trimmed = section.get_data()[:section.Misc_VirtualSize]
        section_entropy = shanon_helper(section_data_trimmed)
        pe_entropy_list.append(section_entropy)
    
    entropy_summary = {'avg_entropy': sum(pe_entropy_list)/len(pe_entropy_list),
                       'max_entropy': max(pe_entropy_list), 
                       'min_entropy': min(pe_entropy_list),
                       'std_entropy': np.std(pe_entropy_list)}
    
    # print(entropy_summary)
    return entropy_summary

# Structural features are used to capture more information about file which will help the model find underlying patterns in the data
def get_structural_features(filepath, pe)-> dict:
    num_sections = len(pe.sections)
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    raw_size = size_of_headers
    virtual_size = size_of_headers
    
    for section in pe.sections:
        raw_size += section.SizeOfRawData
        virtual_size += section.Misc_VirtualSize
    
    virtual_size_ratio = virtual_size/raw_size if raw_size > 0 else 0
    
    structural_features = {
        'num_sections': num_sections,
        'size_of_headers': size_of_headers,
        'raw_size': raw_size,
        'virtual_size': virtual_size,
        'virtual_size_ratio': virtual_size_ratio
    }
    
    return structural_features    

# The main function that will call other functions to generate 1 row per file for the dataset
def extract_all_features(filepath) -> dict:
    pe = None
    try: 
        pe = pefile.PE(filepath)

        features = {
            'filename': os.path.basename(filepath),
            'total_file_size': os.path.getsize(filepath)
        }
        
        features.update(get_entropy_features(pe))
        features.update(get_structural_features(filepath, pe))
    
    except pefile.PEFormatError as e:
        print(f"Error processing {filepath}: {e}")
        features = None
        
    finally:
        if pe is not None:
            pe.close()
    
    return features


sample_malware = 'data/malicious/sgn/shikata_1.exe'
sample_malware_1 = 'data/malicious/custom_malware_bash/custom_loader_1.exe'

result = extract_all_features(sample_malware)
result_1 = extract_all_features(sample_malware_1)

print(result)
print(result_1)

# # example usage for testing normal bash files
# shanon_helper('generate_benign.sh')
# shanon_helper('generate_custom_malware.sh')
# shanon_helper('generate_malicious.sh')
# # example usage for testing malicious pe files
# shanon_helper('data/malicious/custom_malware_bash/custom_loader_1.exe')
# shanon_helper('data/malicious/sgn/shikata_1.exe')
# # example usage for testing benign pe files
# shanon_helper('data/benign/AccountsRt.dll')
# get_entropy_features('data/malicious/sgn/shikata_1.exe')
# get_entropy_features('data/malicious/custom_malware_bash/custom_loader_1.exe')