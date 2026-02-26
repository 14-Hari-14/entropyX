import os
import numpy as np
import lightgbm as lgb
from ember_extractor import PEFeatureExtractor
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix
import time

# --- CONFIGURATION ---
MODEL_PATH = "sorel_lite_model_v1.txt"
BASE_PATH = r"C:\Users\whizhack\Desktop\HardBenign" 
MAX_BYTES = 1024 * 1024  # 1MB limit


def get_lite_indices():
    lite_indices = np.arange(616, 2381)
    return np.delete(lite_indices, np.where(lite_indices == 626)[0])


def evaluate_metrics(y_true, y_pred_probs, threshold=0.5):
    y_pred = (np.array(y_pred_probs) > threshold).astype(int)
    y_true = np.array(y_true)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    print("\n" + "=" * 50)
    print("       FINAL EVALUATION METRICS")
    print("=" * 50)
    print(f"Total Files Processed: {len(y_true)}")
    print(f"Detection Rate (Recall): {recall_score(y_true, y_pred):.4f}")
    print(f"Accuracy:               {accuracy_score(y_true, y_pred):.4f}")
    print("\n[Confusion Matrix]")
    print(f"TP (Caught): {tp} | FN (Missed): {fn}")
    print(f"FP (False Alarm): {fp} | TN (Correct Benign): {tn}")
    print("=" * 50)


def main():
    if not os.path.exists(MODEL_PATH):
        print(f"[-] Model not found: {MODEL_PATH}")
        return

    # --- MODE SELECTION ---
    mode = input("Enter 1 for Malware Scan | 0 for Benign Scan: ").strip()

    if mode not in ["0", "1"]:
        print("Invalid input. Please enter 1 or 0.")
        return

    label = int(mode)
    scan_type = "Malware" if label == 1 else "Benign"

    print(f"\n[*] Running in {scan_type} Mode")
    print(f"[*] Reading only first 1MB of each file\n")

    model = lgb.Booster(model_file=MODEL_PATH)
    extractor = PEFeatureExtractor(feature_version=2)
    lite_indices = get_lite_indices()

    y_true = []
    y_probs = []

    file_count = 0
    start_total = time.time()

    for root, dirs, files in os.walk(BASE_PATH):
        for file in files:
            file_path = os.path.join(root, file)

            try:
                with open(file_path, 'rb') as f:
                    bytez = f.read(MAX_BYTES)  # <-- Only 1MB

                raw_vector = extractor.feature_vector(bytez)
                vector = np.array(raw_vector)[lite_indices]

                prob = model.predict([vector])[0]

                y_probs.append(prob)
                y_true.append(label)

                file_count += 1

                # Print progress every 25 files
                if file_count % 25 == 0:
                    print(f"Processed {file_count} files...")

            except Exception:
                continue  # silently skip non-PE files

    total_time = time.time() - start_total

    if y_true:
        print(f"\n[*] Scan completed in {total_time:.2f} seconds")
        evaluate_metrics(y_true, y_probs)
    else:
        print("[-] No valid PE files were processed.")


if __name__ == "__main__":
    main()