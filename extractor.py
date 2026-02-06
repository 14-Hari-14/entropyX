from collections import Counter
import math

def shanon_helper(filepath):
    counter = Counter()
    entropy = 0.0
    
    # Calculate the frequency of each byte in the file
    with open (filepath, 'rb') as file:
        file_bytes = file.read()
        counter.update(file_bytes)
    
    total_bytes = sum(counter.values())
    
    # Safety check for empty files 
    if total_bytes == 0:
        return 0.0
    
    # Calculate the probability of each byte and use it to calculate entropy of the file
    for count in counter.values():
        prob = count/total_bytes
        entropy -= prob*math.log2(prob)
        
    return entropy

