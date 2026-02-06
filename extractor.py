from collections import Counter
import math

def shanon_helper(filepath):
    counter = Counter()
    entropy = 0.0
    # Calculate the frequency of each byte in the file
    with open (filepath, 'rb') as file:
        file_bytes = file.read()
        counter.update(file_bytes)
    
    # Calculate the probability of each byte
    total_bytes = sum(counter.values())
    # Dictionary Comprehension: {key: new_value for key, old_value in dictionary.items()}
    probabilities = {byte: count / total_bytes for byte, count in counter.items()}
    
    for prob in probabilities.values():
        entropy += prob*math.log2(prob)
    
    entropy = 0.0-entropy
    
    print(entropy)
    return entropy


shanon_helper("/home/hari/Computer_Science/projects/entropyX/generate_benign.sh")