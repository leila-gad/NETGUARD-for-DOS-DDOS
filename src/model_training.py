import os, joblib, pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, roc_auc_score, confusion_matrix,
    classification_report
)

os.makedirs("models",  exist_ok=True)
os.makedirs("results", exist_ok=True)

# 1. LOAD
print(" 1 - Loading data")
X_train = pd.read_csv("data/processed/X_train.csv")
X_test  = pd.read_csv("data/processed/X_test.csv")
y_train = pd.read_csv("data/processed/y_train.csv").squeeze()
y_test  = pd.read_csv("data/processed/y_test.csv").squeeze()
print(f"  X_train: {X_train.shape} | X_test: {X_test.shape}")
neg = (y_train == 0).sum()
pos = (y_train == 1).sum()
spw = round(neg / pos, 2)
print(f"  BENIGN: {neg:,} | ATTACK: {pos:,} | scale_pos_weight: {spw}")

# 2. TRAIN
print("\n 2 - Training XGBoost")
model = XGBClassifier(
    n_estimators=300, max_depth=8, learning_rate=0.05,
    subsample=0.8, colsample_bytree=0.8, scale_pos_weight=spw,
    use_label_encoder=False, eval_metric="logloss",
    random_state=42, n_jobs=-1, verbosity=0
)
model.fit(X_train, y_train)
print("  Done.")

# 3. EVALUATE
print("\n 3 - Evaluating")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_prob)
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1-Score  : {f1*100:.2f}%")
print(f"  ROC-AUC   : {auc*100:.2f}%")
print()
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
with open("results/metrics.txt", "w") as f:
    f.write(f"Accuracy  : {acc*100:.2f}%\nPrecision : {prec*100:.2f}%\n")
    f.write(f"Recall    : {rec*100:.2f}%\nF1-Score  : {f1*100:.2f}%\n")
    f.write(f"ROC-AUC   : {auc*100:.2f}%\n\n")
    f.write(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

# 4. CONFUSION MATRIX
print(" 4 - Confusion matrix")
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["BENIGN", "ATTACK"],
            yticklabels=["BENIGN", "ATTACK"])
plt.title("XGBoost - Confusion Matrix", fontsize=14, fontweight="bold")
plt.ylabel("Actual"); plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("results/confusion_matrix.png", dpi=150)
plt.close()
print("  Saved -> results/confusion_matrix.png")

# 5. SAVE MODEL
print("\n 5 - Saving model")
joblib.dump(model, "models/dos_detector.pkl")
print("  Saved -> models/dos_detector.pkl")
print("\nDONE - Next step: run app.py")