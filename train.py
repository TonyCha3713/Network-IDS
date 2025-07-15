import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
import xgboost as xgb
import matplotlib.pyplot as plt
# --------------------------
# Load Data
# --------------------------

df = pd.read_csv('ml_dataset.csv')
# --------------------------
# Duplicate Rare Classes
# --------------------------

# Define which classes are rare
RARE_CLASSES = ["Exfil","DDoS", "BruteForce", "Misc"]

# How many times to duplicate rare rows
DUPLICATION_FACTOR = 10

# Duplicate rare rows
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

# Fill any missing values
df_augmented = df_augmented.fillna(0)

# Encode categorical columns
df_augmented['Label'] = df_augmented['Label'].astype('category')

# Save mapping for future decoding
label_mapping = dict(enumerate(df_augmented['Label'].cat.categories))
print("Label mapping:", label_mapping)

# Get X and y
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
    n_estimators=400,
    max_depth=8,
    learning_rate=0.1,
    eval_metric='mlogloss',
    random_state=42
)

clf.fit(X_train, y_train)

# --------------------------
# Predict & Report
# --------------------------

y_pred = clf.predict(X_test)

# Convert numeric predictions back to readable labels
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
xgb.plot_importance(clf, max_num_features=20)
plt.show()
joblib.dump(clf, "ids_model.joblib")
print("\nModel saved as ids_model.joblib")

