# Network-IDS
Network Intrusion Detection System with ML models for accurate classification
Built a real-time IDS that captures live network traffic using PyShark and analyzes network flows to detect attacks like port scans, brute force attempts, DDoS floods, and data exfiltration. The system extracts features including packet rates, inter-arrival times, byte volumes, and connection rates, and uses an XGBoost model trained on labeled flow data for accurate classification. Achieved an accuracy of 98.2% during performance across multiple attack types, with the ability to trigger real-time alerts and generate visualizations for monitoring threats. Implemented configurable behavioral thresholds and logging to create an ML-ready dataset, demonstrating how machine learning and traditional network analytics can work together for adaptive threat detection.

https://github.com/user-attachments/assets/abe912da-43c5-4c52-8c78-4a297434b78b

<img width="1778" height="1011" alt="Screenshot 2025-07-14 at 11 36 01 PM" src="https://github.com/user-attachments/assets/73cb4569-c98f-421d-9aa6-60655b6d6f2f" />

<img width="573" height="321" alt="Screenshot 2025-07-14 at 11 37 29 PM" src="https://github.com/user-attachments/assets/c1b3f916-fd51-40d7-8761-d6ca366741e4" />


## Key Features
+ Real-time Prediction: Captures real-time network traffic using PyShark for continuous monitoring.
+ Custom Detection Model: XGBoost model trained on flow-level features to classify network traffic 
+ Behavioral Rules: Custom logic to identify attack types
+ Feature Extraction: Calculates metrics for each network flow for model training
+ Alerts & Visualization: Logs alerts as CSV records and provides live visualizations of attack types and frequencies.

## Source Code Architecture
```
├── ids.py             Main IDS system for live traffic analysis
├── train.py           Trains the machine learning model
├── visualize.py       Live matplotlib visualization
├── predict.py         Live predictions on trained model
```

## Implementation Breakdown

### 1.Data Collection
+ Captures live network traffic using PyShark.
+ Extracts relevant fields such as IP addresses, ports, protocols, packet sizes, and timestamps to support both rule-based and ML-based analysis.
+ Stores flow statistics for each communication session to build an ML-ready dataset.

### 2.Feature Extraction
+ Groups packets into flows defined by a combination of source IP, destination IP, destination port, and protocol, allowing consistent tracking of communication session.
+ Maintains detailed flow statistics, including packet counts, total bytes sent and received, flow duration, packet size distribution, and inter-arrival times (IATs).
+ Extracts relevant fields such as IP addresses, ports, protocols, packet sizes, and timestamps to support both rule-based and ML-based analysisCaptures traffic patterns essential for distinguishing normal vs. attack flows..

### 3.Behavioral Detection Rules
+ Applies threshold-based logic to identify suspicious behavior, such as excessive port scanning, repeated failed connection attempts, or unusually large data transfers.
+ Triggers real-time alerts when behaviors exceed predefined thresholds, enabling immediate detection of active threats like brute force attacks, DDoS floods, or data exfiltration.

### 4.Feature Engineering and Machine Learning
+ Calculates a comprehensive set of flow-level features (e.g. packet rates, average packet sizes, bytes per second, connection rates) to capture traffic characteristics useful for ML classification.
+ Trains an XGBoost model on labeled flow data to learn complex patterns associated with different attack types and predicts the attack category for expired flows to enhance detection beyond static rules.
+ Learning rate: 0.1, Max depth: 8, n_estimators: 400 (tuned for optimal performance).
+ Handles class imbalance with techniques like class weighting or selective duplication during training.

### 5.Logging and Visualization
+ Logs all alerts and flow feature data into structured CSV files, creating a record for further analysis, reporting, or model retraining.
+ Provides a live visualization which enables immediate visibility into the current security status of the network environment.

## Usage
**Note:** Sudo privileges are needed to run traffic analysis 
+ Live Visualization: `python3 visualize.py`
+ Model Training: `python3 train.py`
+ Live traffic analysis: `python3 ids.py`
+ Live Machine lpreidction: `python3 predict.py`

## Testing
+ **Port Scanning** `nmap -p- -sV <target_ip>`
+ **Brute Force** `hydra -l user -P <wordlist.txt> ssh://<target_ip>`
+ **DDoS** `ping -c 5000 -i 0.01 <target_ip>`
+ **Exfil** `scp file.zip user@<target_ip>:/`

## Security Recommendations for IDS
+ Adjust thresholds to match normal network behavior and reduce false positives, especially in environments with varying traffic volumes.
+ Run the IDS with the minimum permissions necessary and avoid executing it as root unless absolutely required for packet capture.
+ Regularly rotate and securely store logs, as IDS alerts can contain sensitive data such as IP addresses and potential attack indicators.
+ Continuously monitor new attack techniques and update detection rules and machine learning models to keep pace with evolving threats.


