from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
import numpy as np
import time
import os
import warnings
warnings.filterwarnings("ignore")

# Load models and encoders
print("Loading models and encoders...")
model = joblib.load('model_dir/ids_model.pkl')
protocol_encoder = joblib.load('data_dir/protocol_type_encoder.pkl')
service_encoder = joblib.load('data_dir/service_encoder.pkl')
flag_encoder = joblib.load('data_dir/flag_encoder.pkl')
scaler = joblib.load('data_dir/scaler.pkl')

# Directory to store logs
os.makedirs('logs', exist_ok=True)
log_file = f'logs/intrusion_log_{int(time.time())}.txt'
port_scan_log = f'logs/port_scan_log_{int(time.time())}.txt'
packet_log_file = f'logs/packet_log_{int(time.time())}.csv'
aggressive_log = f'logs/aggressive_log_{int(time.time())}.txt'

# Mapping protocol types
PROTOCOLS = {
    6: 'tcp',
    17: 'udp',
    1: 'icmp'
}

# TCP Flag Mappings to match NSL-KDD
TCP_FLAG_MAP = {
    'S': 'S0',
    'SA': 'SF',
    'R': 'REJ',
    'FA': 'RSTO',
    'F': 'RSTO',
    'PA': 'S1',
    'OTH': 'OTH'
}

# Map common ports to services
SERVICE_PORTS = {
    80: 'http',
    443: 'https',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    110: 'pop3',
    143: 'imap',
    3306: 'mysql',
    8080: 'http-alt'
}

MONITORED_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    8080: 'HTTP-ALT'
}

# Threshold values (aggressive)
THRESHOLD_SYN = 10         # 10 SYN packets in 5 seconds
THRESHOLD_CONNECTIONS = 25 # 25 connections in 5 seconds
THRESHOLD_PORT_SCAN = 3    # 3 hits on critical ports
THRESHOLD_UDP = 15         # 15 UDP packets in 5 seconds
RESET_INTERVAL = 5         # Reset counters every 5 seconds

# Complete List of Features with Aggressive Defaults
TRAIN_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]
# Default Values
DEFAULT_VALUES = {feature: 0 for feature in TRAIN_FEATURES}
DEFAULT_VALUES.update({
    'serror_rate': 0.05,
    'srv_serror_rate': 0.05,
    'rerror_rate': 0.05,
    'srv_rerror_rate': 0.05,
    'same_srv_rate': 0.05,
})
connection_tracker = {}
port_tracker = {port: 0 for port in MONITORED_PORTS}

def get_tcp_flag(packet):
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        flag_str = str(flags)
        return TCP_FLAG_MAP.get(flag_str, 'OTH')
    return 'OTH'

def extract_features(packet):
    try:
        if not packet.haslayer(IP):
            return None
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else -1
        
        # Initialize tracking if new IP
        current_time = time.time()
        if src_ip not in connection_tracker:
            connection_tracker[src_ip] = DEFAULT_VALUES.copy()
            connection_tracker[src_ip]['start_time'] = current_time

        # Time-based reset
        if current_time - connection_tracker[src_ip]['start_time'] > RESET_INTERVAL:
            connection_tracker[src_ip] = DEFAULT_VALUES.copy()
            connection_tracker[src_ip]['start_time'] = current_time

        # Update connection count
        connection_tracker[src_ip]['count'] += 1
        
        # Detect SYN errors (SYN with no ACK)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            connection_tracker[src_ip]['serror_rate'] += 0.2

        # Detect UDP floods
        if packet.haslayer(UDP):
            connection_tracker[src_ip]['srv_count'] += 1

        # Threshold-Based Detection
        if connection_tracker[src_ip]['serror_rate'] >= THRESHOLD_SYN and packet.haslayer(TCP):
            alert_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [ALERT] SYN Flood Detected from {src_ip}"
            print(alert_msg)
            with open(aggressive_log, 'a') as f:
                f.write(alert_msg + "\n")
        
        if dst_port in MONITORED_PORTS:
            port_tracker[dst_port] += 1
            print(f"[DEBUG] Port {dst_port} ({MONITORED_PORTS[dst_port]}) scanned by {src_ip}")
            
            if port_tracker[dst_port] >= THRESHOLD_PORT_SCAN:
                alert_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [ALERT] Port Scan Detected: {MONITORED_PORTS[dst_port]} from {src_ip} 🚨"
                print(alert_msg)
                with open(port_scan_log, 'a') as f:
                    f.write(alert_msg + "\n")
                port_tracker[dst_port] = 0  # Reset after trigger

        if connection_tracker[src_ip]['srv_count'] >= THRESHOLD_UDP and packet.haslayer(UDP):
            alert_msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [ALERT] UDP Flood Detected from {src_ip}"
            print(alert_msg)
            with open(aggressive_log, 'a') as f:
                f.write(alert_msg + "\n")
        
        # Proceed with feature extraction
        protocol = PROTOCOLS.get(packet.proto, 'other')
        service = SERVICE_PORTS.get(dst_port, 'other')
        flag = get_tcp_flag(packet)
        
        # Encoding Logic
        if protocol in protocol_encoder.classes_:
            protocol_encoded = protocol_encoder.transform([protocol])[0]
        else:
            print(f"[WARNING] Protocol '{protocol}' not recognized. Defaulting to 'other'.")
            protocol_encoded = protocol_encoder.transform(['other'])[0]

        if service in service_encoder.classes_:
            service_encoded = service_encoder.transform([service])[0]
        else:
            print(f"[WARNING] Service '{service}' not recognized. Defaulting to 'other'.")
            service_encoded = service_encoder.transform(['other'])[0]

        if flag in flag_encoder.classes_:
            flag_encoded = flag_encoder.transform([flag])[0]
        else:
            print(f"[WARNING] Flag '{flag}' not recognized. Defaulting to 'OTH'.")
            flag_encoded = flag_encoder.transform(['OTH'])[0]

        # Updated Feature Dictionary
        features = DEFAULT_VALUES.copy()
        features.update({
            'protocol_type': protocol_encoded,  # <-- Now encoded as an integer
            'service': service_encoded,         # <-- Now encoded as an integer
            'flag': flag_encoded,               # <-- Now encoded as an integer
        })

        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)
        return features_scaled

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def detect_intrusion(packet):
    features = extract_features(packet)
    if features is not None:
        prediction = model.predict(features)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        if prediction == 1:
            alert_msg = f"[{timestamp}] [ALERT] Intrusion Detected from {packet[IP].src} 🚨"
            print(alert_msg)
            with open(log_file, 'a') as f:
                f.write(alert_msg + "\n")
        else:
            print(f"[{timestamp}] [INFO] Normal Traffic from {packet[IP].src} ✔️")

# Start sniffing (promiscuous mode to capture all packets)
print("Starting live traffic detection...")
sniff(filter="ip", prn=detect_intrusion, store=0)
