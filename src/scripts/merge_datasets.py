import pandas as pd

# Load both datasets
df1 = pd.read_csv('/home/hari/Computer_Science/projects/entropyX/data/ember/features_benign_2024_v2.csv')
df2 = pd.read_csv('/home/hari/Computer_Science/projects/entropyX/data/ember/features_malicious_2024_v2.csv')
# df3 = pd.read_csv('../data/dataset_ember_2024.csv')

print(f"Dataset 1: {len(df1)} rows")
print(f"Dataset 2: {len(df2)} rows")
# print(f"Dataset 3: {len(df3)} rows")
# Merge (concatenate)
merged = pd.concat([df1, df2], ignore_index=True)

# Shuffle
merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Merged & Shuffled: {len(merged)} rows")

# Save
merged.to_csv('/home/hari/Computer_Science/projects/entropyX/data/ember/dataset_ember_2024_merged_v2.csv', index=False)
print("Saved to /home/hari/Computer_Science/projects/entropyX/data/ember/dataset_ember_2024_merged_v2.csv")