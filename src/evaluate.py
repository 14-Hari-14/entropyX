import numpy as np
import pandas as pd
import lightgbm as lgb

from config import FEATURE_COLS
from sklearn.metrics import confusion_matrix, accuracy_score

DATA_PATH = "../data/test_real/vaulted_test_set.csv"
MODEL_PATH = "../model/ember_lite_model_2024.txt"
THRESHOLD = 0.5


def count_binary(values: pd.Series | np.ndarray) -> tuple[int, int]:
    series = pd.Series(values)
    counts = series.value_counts().reindex([0, 1], fill_value=0)
    return int(counts.loc[0]), int(counts.loc[1])


def main() -> None:
	df = pd.read_csv(DATA_PATH)

	if "label" not in df.columns:
		raise ValueError("The dataset must contain a 'label' column.")

	true_labels = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
	if not true_labels.isin([0, 1]).all():
		raise ValueError("The 'label' column must contain only binary values: 0 or 1.")

	true_0, true_1 = count_binary(true_labels)

	print(f"[*] Loaded dataset: {DATA_PATH}")
	print(f"[*] Total rows: {len(df)}")
	print(f"[*] True label counts -> 0: {true_0}, 1: {true_1}")

	X_df = df.drop(columns=["label"])
	feat_cols = [col for col in FEATURE_COLS if col in X_df.columns]
	if not feat_cols:
		raise ValueError("No model feature columns were found in the dataset.")

	for col in feat_cols:
		X_df[col] = pd.to_numeric(X_df[col], errors="coerce").astype(np.float32)

	X = X_df[feat_cols].values

	model = lgb.Booster(model_file=MODEL_PATH)
	y_prob = model.predict(X)
	y_pred = (y_prob >= THRESHOLD).astype(int)

	pred_0, pred_1 = count_binary(y_pred)
	tn, fp, fn, tp = confusion_matrix(true_labels, y_pred, labels=[0, 1]).ravel()
	accuracy = accuracy_score(true_labels, y_pred)

	fpr = fp / (fp + tn) if (fp + tn) else 0.0
	fnr = fn / (fn + tp) if (fn + tp) else 0.0

	print(f"[*] Model evaluated: {MODEL_PATH}")
	print(f"[*] Prediction threshold: {THRESHOLD}")
	print(f"[*] Predicted label counts -> 0: {pred_0}, 1: {pred_1}")

	print("\n[*] Summary")
	print(f"    Actual    -> 0: {true_0}, 1: {true_1}")
	print(f"    Predicted -> 0: {pred_0}, 1: {pred_1}")

	print("\n[*] Confusion Matrix")
	print(f"    TN: {tn}")
	print(f"    FP: {fp}")
	print(f"    FN: {fn}")
	print(f"    TP: {tp}")

	print("\n[*] Metrics")
	print(f"    Accuracy: {accuracy:.4f}")
	print(f"    FPR: {fpr * 100:.2f}%")
	print(f"    FNR: {fnr * 100:.2f}%")

	# --- THE AUTOPSY ---
	# Find the exact rows where the model blocked a benign file
	true_labels_series = pd.Series(true_labels.values, index=df.index)
	pred_series = pd.Series(y_pred, index=df.index)
	fp_mask = (true_labels_series == 0) & (pred_series == 1)
	fp_df = df[fp_mask].copy()

	AUTOPSY_FILE = "false_positives_autopsy.csv"
	fp_df.to_csv(AUTOPSY_FILE, index=False)
	print(f"\n[!] AUTOPSY: Dumped the {len(fp_df)} False Positives to {AUTOPSY_FILE}")
    
    
	print("\n[*] --- THRESHOLD SWEEP ---")
	for thresh in [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
		y_pred_thresh = (y_prob >= thresh).astype(int)
		tn, fp, fn, tp = confusion_matrix(true_labels, y_pred_thresh, labels=[0, 1]).ravel()
		fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
		fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
		print(f"  Thresh {thresh:.2f} | FPR: {fpr * 100:5.1f}% | FNR: {fnr * 100:5.1f}% | FP: {fp:<3} | TP: {tp}")
  


if __name__ == "__main__":
	main()
