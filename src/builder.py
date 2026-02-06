# File to compile the extracted features into a dataset for training the model

import os
import csv
from extractor import extract_all_features

BENIGN_PATH = '../data/benign/'
MALICIOUS_PATH = '../data/malicious/'
OUTPUT_CSV = '../data/dataset.csv'

column_headers = extract_all_features('../data/malicious/sgn/shikata_1.exe').keys()

column_headers = list(column_headers)
column_headers.append('is_malicious')

with open(OUTPUT_CSV, mode='w', newline='') as csv_file:
    rows = []
    writer = csv.DictWriter(csv_file, fieldnames=column_headers)
    writer.writeheader()
    
    for root, dirs, files in os.walk('../data/benign', topdown=True):
        for file in files:
            row = extract_all_features(file)
            if row is not None:
                row['is_malicious'] = 0
                rows.append(row)
    
    for file in os.walk('../data/malicious', topdown=True):
        row = extract_all_features(file)
        if row is not None:
            row['is_malicious'] = 1
            rows.append(row) 
    
    writer.writerows(rows) 