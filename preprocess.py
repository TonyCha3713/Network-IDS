import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

# Create directory for processed data and models
os.makedirs('data_dir', exist_ok=True)

# Read the dataset
print("Loading dataset...")
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

data = pd.read_csv('KDDTrain+.txt', names=column_names, header=None)

# Select All Features
selected_columns = column_names[:-2]  # Exclude 'label' and 'difficulty'

# Encode categorical features
print("Encoding categorical features...")
categorical_cols = list(set(['protocol_type', 'service', 'flag']) & set(data.columns))
for col in categorical_cols:
    if data[col].dtype == 'object':
        encoder = LabelEncoder()
        data[col] = encoder.fit_transform(data[col].astype(str))
        joblib.dump(encoder, f'data_dir/{col}_encoder.pkl')

# Separate features and labels
print("Preparing features and labels...")
X = data[selected_columns]
y = data['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Standardize features
print("Standardizing features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'data_dir/scaler.pkl')

# Save processed data
print("Saving preprocessed data...")
pd.DataFrame(X_scaled, columns=selected_columns).to_csv('data_dir/X_train.csv', index=False)
pd.DataFrame(y, columns=['label']).to_csv('data_dir/y_train.csv', index=False)

print("Preprocessing complete. Data saved to data_dir folder.")

