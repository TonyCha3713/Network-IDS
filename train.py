import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Create directory for models if it doesn't exist
os.makedirs('model_dir', exist_ok=True)

# Load preprocessed data
print("Loading preprocessed data...")
X = pd.read_csv('data_dir/X_train.csv')
y = pd.read_csv('data_dir/y_train.csv')

# Display the shape of the data
print(f"Feature set shape: {X.shape}")
print(f"Labels shape: {y.shape}")

# Split the data
print("Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the model
print("Training the RandomForest model with all 41 features...")
model = RandomForestClassifier(n_estimators=300, random_state=42, max_depth=25, n_jobs=-1)
model.fit(X_train, y_train.values.ravel())

# Evaluate the model
print("Evaluating the model...")
y_pred = model.predict(X_test)
print("\nAccuracy Score:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save the model
model_path = 'model_dir/ids_model.pkl'
print(f"Saving the model to {model_path}...")
joblib.dump(model, model_path)

print("Training complete. Model saved successfully.")

