from collections import Counter
import math
import pefile 

def shanon_helper(binary_data):
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
def extract_pe_entropy(filepath):
    pe = pefile.PE(filepath)
    pe_entropy_list  = []
    for section in pe.sections:
        section_data_trimmed = section.get_data()[:section.Misc_VirtualSize]
        section_entropy = shanon_helper(section_data_trimmed)
        pe_entropy_list.append(section_entropy)
        
    print(pe_entropy_list)
    return pe_entropy_list


# # example usage for testing normal bash files
# shanon_helper('generate_benign.sh')
# shanon_helper('generate_custom_malware.sh')
# shanon_helper('generate_malicious.sh')
# # example usage for testing malicious pe files
# shanon_helper('data/malicious/custom_malware_bash/custom_loader_1.exe')
# shanon_helper('data/malicious/sgn/shikata_1.exe')
# # example usage for testing benign pe files
# shanon_helper('data/benign/AccountsRt.dll')

extract_pe_entropy('data/malicious/sgn/shikata_1.exe')
extract_pe_entropy('data/malicious/custom_malware_bash/custom_loader_1.exe')
