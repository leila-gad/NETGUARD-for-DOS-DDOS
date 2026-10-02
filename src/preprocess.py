import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from collections import Counter

DATA_FILES = [
    "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "data/raw/Wednesday-WorkingHours.pcap_ISCX.csv",
    "data/raw/Monday-WorkingHours.pcap_ISCX.csv",
]

OUTPUT_DIR   = "data/processed"
MODELS_DIR   = "models"
LABEL_COL    = "Label"          
TEST_SIZE    = 0.2
RANDOM_STATE = 42

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

# 1. LOAD & MERGE ALL THREE FILES
print(" 1 — Loading and merging datasets")
frames = []
for path in DATA_FILES:
    print(f"  Loading: {path}")
    df_tmp = pd.read_csv(path, low_memory=False)
    df_tmp.columns = df_tmp.columns.str.strip()   # remove hidden spaces
    print(f"    -> {df_tmp.shape[0]:,} rows, {df_tmp.shape[1]} columns")
    frames.append(df_tmp)

df = pd.concat(frames, ignore_index=True)
print(f"\n  Combined shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

# 2. INSPECT RAW LABEL DISTRIBUTION
print(" 2 — Raw label distribution")
print(df[LABEL_COL].value_counts())

# 3. BINARY LABELLING
print(" 3 — Binary labelling  (BENIGN=0, ATTACK=1)")
df["label"] = df[LABEL_COL].str.strip().apply(
    lambda x: 0 if x.upper() == "BENIGN" else 1
)
df.drop(columns=[LABEL_COL], inplace=True)

benign  = (df["label"] == 0).sum()
attacks = (df["label"] == 1).sum()
print(f"  BENIGN : {benign:,}  ({benign / len(df) * 100:.1f}%)")
print(f"  ATTACK : {attacks:,}  ({attacks / len(df) * 100:.1f}%)")

# 4. DROP DUPLICATE COLUMNS
print(" 4 — Dropping duplicate columns")
before = df.shape[1]
df = df.loc[:, ~df.columns.duplicated()]
after = df.shape[1]
print(f"  Removed {before - after} duplicate column(s). Remaining: {after}")

# 5. HANDLE INFINITE AND MISSING VALUES
print(" 5 — Handling Inf and NaN values")
inf_count = np.isinf(df.select_dtypes(include=np.number)).sum().sum()
print(f"  Infinite values found : {inf_count:,}")
df.replace([np.inf, -np.inf], np.nan, inplace=True)

nan_count = df.isnull().sum().sum()
print(f"  NaN values found      : {nan_count:,}")
df.fillna(df.median(numeric_only=True), inplace=True)
print(f"  NaN values after fill : {df.isnull().sum().sum()}")

# 6. DROP ZERO-VARIANCE COLUMNS
print(" 6 — Dropping zero-variance columns")
feature_cols = [c for c in df.columns if c != "label"]
X_tmp = df[feature_cols]
zero_var = X_tmp.columns[X_tmp.nunique() <= 1].tolist()

if zero_var:
    print(f"  Dropping {len(zero_var)} constant column(s): {zero_var}")
    df.drop(columns=zero_var, inplace=True)
else:
    print("  No zero-variance columns found.")

# 7. SPLIT FEATURES AND LABEL
print(" 7 — Splitting features and label")
feature_cols = [c for c in df.columns if c != "label"]
X = df[feature_cols].astype(np.float32)
y = df["label"].astype(np.int32)

print(f"\n  Feature matrix : {X.shape}")
print(f"  Label vector   : {y.shape}")

# 8. TRAIN / TEST SPLIT  (stratified, no leakage)
print(" 8 — Train / Test split  (80 / 20, stratified)")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)

print(f"  X_train : {X_train.shape}")
print(f"  X_test  : {X_test.shape}")
print(f"  Train class dist : {Counter(y_train.tolist())}")
print(f"  Test  class dist : {Counter(y_test.tolist())}")

# 9. NORMALIZE 
print(" 9 — Normalizing features (MinMaxScaler)")
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)   
X_test_scaled  = scaler.transform(X_test)         
X_train_df = pd.DataFrame(X_train_scaled, columns=feature_cols)
X_test_df  = pd.DataFrame(X_test_scaled,  columns=feature_cols)

print("  Scaler fitted on training data only (prevents data leakage).")

# 10. SAVE ALL OUTPUTS
print(" 10 — Saving processed files")
X_train_df.to_csv(f"{OUTPUT_DIR}/X_train.csv", index=False)
X_test_df.to_csv(f"{OUTPUT_DIR}/X_test.csv",   index=False)
y_train.to_csv(f"{OUTPUT_DIR}/y_train.csv",     index=False)
y_test.to_csv(f"{OUTPUT_DIR}/y_test.csv",       index=False)

joblib.dump(scaler,       f"{MODELS_DIR}/scaler.pkl")
joblib.dump(feature_cols, f"{MODELS_DIR}/feature_names.pkl")

print(f"  X_train.csv      -> {OUTPUT_DIR}/")
print(f"  X_test.csv       -> {OUTPUT_DIR}/")
print(f"  y_train.csv      -> {OUTPUT_DIR}/")
print(f"  y_test.csv       -> {OUTPUT_DIR}/")
print(f"  scaler.pkl       -> {MODELS_DIR}/")
print(f"  feature_names    -> {MODELS_DIR}/")

# 11. FINAL SUMMARY
print("PREPROCESSING COMPLETE")
print(f"  Total samples  : {len(df):,}")
print(f"  Total features : {len(feature_cols)}")
print(f"  Training set   : {X_train_df.shape[0]:,} samples")
print(f"  Test set       : {X_test_df.shape[0]:,} samples")
print(f"  Attack ratio   : {attacks / len(df) * 100:.1f}%")
print("\n  Next step -> run train.py")