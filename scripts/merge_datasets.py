import pandas as pd

# Load both datasets
df1 = pd.read_csv('../data/dataset_ember_benign.csv')
df2 = pd.read_csv('../data/dataset_ember_malware_actual.csv')
df3 = pd.read_csv('../data/dataset_ember_custom_mal.csv')

print(f"Dataset 1: {len(df1)} rows")
print(f"Dataset 2: {len(df2)} rows")
print(f"Dataset 3: {len(df3)} rows")
# Merge (concatenate)
merged = pd.concat([df1, df2, df3], ignore_index=True)

# Shuffle
merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Merged & Shuffled: {len(merged)} rows")

# Save
merged.to_csv('../data/dataset_ember_merged.csv', index=False)
print("Saved to ../data/dataset_ember_merged.csv")