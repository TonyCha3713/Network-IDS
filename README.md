# Network-IDS
Network Intrusion Detection System with ML models for accurate classification
Developed a real-time Intrusion Detection System (IDS) leveraging the NSL-KDD dataset to identify malicious network activities, including port scans, SYN floods, UDP floods, ICMP attacks, and brute force attempts. The system uses a Random Forest Classifier trained on 41 network features, achieving an accuracy of 94.3% during evaluation. Implemented live packet sniffing with Scapy to analyze traffic, detect anomalies, and trigger real-time alerts, monitored critical ports like SSH (22), HTTP (80), and MySQL (3306) with threshold-based detection for early attack prevention.

## Demo
https://github.com/user-attachments/assets/c8e7c35e-b955-4bc4-9d5f-7eb54f1605c7

## Key Features
+ Real-time packet sniffing and anomaly detection
+ Threshold-based alerts for aggressive scanning
+ Detection of ICMP floods, ARP spoofing, and DNS poisoning
+ Auto-detection of critical port scans with live alerts
+ Comprehensive logging of network intrusions and suspicious activities

## Source Code Architecture
```
├── preprocess.py      Preprocesses the NSL-KDD dataset
├── train.py           Trains the machine learning model
├── ids.py             Main IDS system for live traffic analysis
├── data_dir/          Stores processed datasets and encoders
├── model_dir/         Stores the trained machine learning model  
```

## Usage
**Note:** Sudo privileges are needed to run traffic analysis 
+ Preprocessing: `python3 preprocess.py`
+ Model Training: `python3 train.py`
+ Live traffic analysis: `python3 ids.py`

## Testing
+ **Port Scanning** `nmap -p- -sV <target_ip>`
+ **SYN Flooding** `hping3 -S -p 80 --flood <target_ip>`
+ **UDP Scanning** `nmap -sU -sV <target_ip>`
+ **ICMP Flooding** `ping -f <target_ip>`
+ **Brute Force Attack** `hydra -l admin -P <wordlist> ssh://<target_ip>`

## Configuration
You can adjust the following in `ids.py`
+ **Thresholds for detection:**
  + SYN Flood: `THRESHOLD_SYN`
  + Connection Flood: `THRESHOLD_CONNECTIONS`
  + UDP Flood: `THRESHOLD_UDP`
  + Port Scans: `THRESHOLD_PORT_SCAN`
+ **Monitored Ports:**
  + Add or remove from `MONITORED_PORTS` dictionary
 
## Logs and Analysis 
+ logs/intrusion_log -> General intrusion
+ logs/port_scan -> Port scan attempts
+ logs/aggressive_log -> High risk aggressive scans

## Security Recommendations
+ Use strong firewall rules alongside the IDS
+ Regularly update the blocklist for known attackers
+ Monitor logs frequently for new attack patterns
