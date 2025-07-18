import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
import xgboost as xgb
import matplotlib.pyplot as plt

# --------------------------
# Load Data
# --------------------------
try:
    df = pd.read_csv('ml_dataset.csv')
except FileNotFoundError:
    print("ml_dataset.csv not found. Please generate the dataset first.")
    exit(1)

# --------------------------
# Duplicate Rare Classes
# --------------------------

# Define which classes are rare
RARE_CLASSES = ["Exfil","DDoS", "BruteForce", "Misc", "PortScan"]

# How many times to duplicate rare rows
DUPLICATION_FACTOR = 3

df_augmented = df.copy()
for rare_class in RARE_CLASSES:
    rare_rows = df[df["Label"] == rare_class]
    if len(rare_rows) > 0:
        duplicated = pd.concat([rare_rows]*DUPLICATION_FACTOR, ignore_index=True)
        df_augmented = pd.concat([df_augmented, duplicated], ignore_index=True)

print(df_augmented["Label"].value_counts())

# --------------------------
# Preprocessing
# --------------------------
df_augmented = df_augmented.fillna(0)
df_augmented['Label'] = df_augmented['Label'].astype('category')
label_mapping = dict(enumerate(df_augmented['Label'].cat.categories))
print("Label mapping:", label_mapping)

X = df_augmented.drop('Label', axis=1)
y = df_augmented['Label'].cat.codes

# --------------------------
# Train/Test Split
# --------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# --------------------------
# Train XGBoost
# --------------------------
clf = XGBClassifier(
    n_estimators=800,
    max_depth=10,
    learning_rate=0.1,
    eval_metric='mlogloss',
    random_state=42
)

# Create a weight array: higher for DDoS, 1 for others
weights = df_augmented['Label'].apply(lambda x: 3 if x == 'DDoS' else 1)

# Fit the model
clf.fit(X_train, y_train, sample_weight=weights.loc[X_train.index])

# --------------------------
# Predict & Report
# --------------------------
y_pred = clf.predict(X_test)
y_pred_labels = [label_mapping[x] for x in y_pred]
y_test_labels = [label_mapping[x] for x in y_test]

print("\nClassification Report:\n")
print(classification_report(
    y_test_labels,
    y_pred_labels,
))

# --------------------------
# Save Model
# --------------------------
try:
    joblib.dump(clf, "ids_model.joblib")
    print("\nModel saved as ids_model.joblib")
except Exception as e:
    print(f"Error saving model: {e}")
