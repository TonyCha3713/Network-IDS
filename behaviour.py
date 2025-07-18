import pyshark
import csv
import time
import os
import json
import numpy as np
from collections import defaultdict
import joblib
import pandas as pd

clf = joblib.load("ids_model.joblib")
with open("label_mapping.json") as f:
    label_mapping = json.load(f)
label_mapping = {int(k): v for k, v in label_mapping.items()}
# -----------------------------
# IDS thresholds
# -----------------------------

PORT_SCAN_PORT_THRESHOLD = 200
PORT_SCAN_TIME_WINDOW = 20

BRUTE_FORCE_ATTEMPTS_THRESHOLD = 300
BRUTE_FORCE_TIME_WINDOW = 15
AVG_PKT_SIZE_THRESHOLD = 60

DDOS_PACKETS_PER_SEC_THRESHOLD = 5000

EXFIL_BYTES_THRESHOLD = 50_000_000

RATE_THRESHOLD = 5000
FLOW_TIMEOUT = 150
ALERT_RETENTION_SECONDS = 600

# -----------------------------
# Data structures
# -----------------------------

flows = defaultdict(lambda: {
    "first_seen": None,
    "last_seen": None,
    "duration": 0,
    "total_fwd_packets": 0,
    "total_bwd_packets": 0,
    "total_bytes_fwd": 0,
    "total_bytes_bwd": 0,
    "protocol": "",
    "packet_sizes": [],
    "iat_list": [],
    "connections_per_minute": 0,
    "packet_timestamps": [],
})

flow_labels = dict()
active_alerts = list()

scan_table = defaultdict(list)
brute_table = defaultdict(list)
ddos_table = defaultdict(list)
exfil_table = defaultdict(float)
connection_table = defaultdict(list)

# -----------------------------
# CSV Files
# -----------------------------

if os.path.exists("ids_alerts.csv"):
    alert_csv = open("ids_alerts.csv", "a", newline="")
    alert_writer = csv.writer(alert_csv)
else:
    alert_csv = open("ids_alerts.csv", "w", newline="")
    alert_writer = csv.writer(alert_csv)
    alert_writer.writerow(["timestamp", "attack_type", "src_ip", "dst_ip", "dst_port", "protocol", "info"])

# ML CSV
if os.path.exists("ml_dataset.csv"):
    ml_csv = open("ml_dataset.csv", "a", newline="")
    ml_writer = csv.writer(ml_csv)
else:
    ml_csv = open("ml_dataset.csv", "w", newline="")
    ml_writer = csv.writer(ml_csv)
    ml_writer.writerow([
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "Avg Packet Size",
        "Pkt Size Std",
        "Min Packet Length",
        "Max Packet Length",
        "Flow IAT Mean",
        "Flow IAT Max",
        "Flow IAT Min",
        "Connections Per Minute",
        "Label"
    ])

# -----------------------------
# Logging & Labeling
# -----------------------------

def log_alert(timestamp, attack_type, src_ip, dst_ip, dst_port, protocol, info):
    alert_writer.writerow([timestamp, attack_type, src_ip, dst_ip, dst_port, protocol, info])
    alert_csv.flush()

    active_alerts.append({
        "attack_type": attack_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp": timestamp
    })

# -----------------------------
# Attack Checks
# -----------------------------

def check_port_scan(src_ip, dst_port, timestamp):
    scan_table[src_ip].append((dst_port, timestamp))
    scan_table[src_ip] = [
        (port, t) for port, t in scan_table[src_ip]
        if timestamp - t < PORT_SCAN_TIME_WINDOW
    ]
    unique_ports = set([p for p, t in scan_table[src_ip]])

    if len(unique_ports) >= PORT_SCAN_PORT_THRESHOLD:
        log_alert(timestamp, "PortScan", src_ip, "", "", "", f"Ports scanned: {len(unique_ports)}")
        scan_table[src_ip] = []

def check_brute_force(src_ip, dst_ip, dst_port, timestamp):
    key = (src_ip, dst_ip, dst_port)
    brute_table[key].append(timestamp)
    brute_table[key] = [
        t for t in brute_table[key]
        if timestamp - t < BRUTE_FORCE_TIME_WINDOW
    ]
    if len(brute_table[key]) >= BRUTE_FORCE_ATTEMPTS_THRESHOLD:
        log_alert(timestamp, "BruteForce", src_ip, dst_ip, dst_port, "", f"Attempts: {len(brute_table[key])}")
        brute_table[key] = []

def check_ddos(dst_ip, packet_size, timestamp):
    ddos_table[dst_ip].append((packet_size, timestamp))
    ddos_table[dst_ip] = [
        (size, t) for size, t in ddos_table[dst_ip]
        if timestamp - t < 1
    ]
    if len(ddos_table[dst_ip]) > DDOS_PACKETS_PER_SEC_THRESHOLD:
        log_alert(timestamp, "DDoS", "", dst_ip, "", "", f"Packets/sec: {len(ddos_table[dst_ip])}")
        ddos_table[dst_ip] = []

def check_exfil(src_ip, length, timestamp):
    exfil_table[src_ip] += length
    if exfil_table[src_ip] > EXFIL_BYTES_THRESHOLD:
        log_alert(timestamp, "Exfiltration", src_ip, "", "", "", f"Total bytes sent: {exfil_table[src_ip]}")
        exfil_table[src_ip] = 0
        label_all_flows_from_src(src_ip, "Exfiltration")

def check_connection_rate(src_ip, timestamp, flow_key):
    connection_table[src_ip].append(timestamp)
    window = [t for t in connection_table[src_ip] if timestamp - t < 60]
    connection_table[src_ip] = window
    connections_per_minute = len(window)

# Save this as a feature in the current flow
    flows[flow_key]["connections_per_minute"] = connections_per_minute

def expire_old_alerts(current_time):
    global active_alerts
    active_alerts = [
        alert for alert in active_alerts
        if current_time - alert["timestamp"] <= ALERT_RETENTION_SECONDS
    ]

# -----------------------------
# Flow Label Helpers
# -----------------------------

def label_all_flows_from_src(src_ip, label):
    for fk in flows:
        if fk[0] == src_ip:
            flow_labels[fk] = label

def map_label(original_label):
    if original_label in ["PortScan", "HighConnectionRate"]:
        return "PortScan"
    elif original_label == "BruteForce":
        return "BruteForce"
    elif original_label == "DDoS":
        return "DDoS"
    elif original_label == "Exfiltration":
        return "Exfil"
    else:
        return "Misc"

# -----------------------------
# Label Expired Flows Correctly
# -----------------------------

def label_expired_flow(flow_key, flow):
    original_label = flow_labels.get(flow_key, "Misc")

    for alert in active_alerts:
        if alert["attack_type"] == "Exfiltration":
            if (
                alert["src_ip"] == flow_key[0] and
                flow["last_seen"] >= alert["timestamp"] - 60 and
                flow["first_seen"] <= alert["timestamp"] + 60 and
                (flow["total_bytes_fwd"] + flow["total_bytes_bwd"]) > 50_000_000
            ):
                return "Exfil"

        if alert["attack_type"] == "DDoS":
            if (
                alert["dst_ip"] == flow_key[1] and
                flow["last_seen"] >= alert["timestamp"] - 30 and
                flow["first_seen"] <= alert["timestamp"] + 30
            ):
                return "DDoS"

        if alert["attack_type"] == "PortScan":
            if (
                alert["src_ip"] == flow_key[0] and
                flow["last_seen"] >= alert["timestamp"] - 60 and
                flow["first_seen"] <= alert["timestamp"] + 60
            ):
                return "PortScan"

        if alert["attack_type"] == "BruteForce":
            if (
                alert["src_ip"] == flow_key[0] and
                alert["dst_ip"] == flow_key[1] and
                flow["last_seen"] >= alert["timestamp"] - 30 and
                flow["first_seen"] <= alert["timestamp"] + 30
            ):
                return "BruteForce"

    return map_label(original_label)

# -----------------------------
# Flow Expiration
# -----------------------------

def expire_flows(current_time):
    expired = []
    for flow_key, flow in flows.items():
        if current_time - flow["last_seen"] > FLOW_TIMEOUT:
            expired.append((flow_key, flow))

    for fk, flow in expired:
        duration = flow["duration"]
        total_fwd_pkts = flow["total_fwd_packets"]
        total_bwd_pkts = flow["total_bwd_packets"]
        total_fwd_bytes = flow["total_bytes_fwd"]
        total_bwd_bytes = flow["total_bytes_bwd"]

        total_bytes = total_fwd_bytes + total_bwd_bytes
        total_pkts = total_fwd_pkts + total_bwd_pkts

        flow_bytes_per_s = (total_bytes / duration) if duration > 0 else 0
        flow_pkts_per_s = (total_pkts / duration) if duration > 0 else 0

        fwd_pkt_len_mean = (total_fwd_bytes / total_fwd_pkts) if total_fwd_pkts > 0 else 0
        bwd_pkt_len_mean = (total_bwd_bytes / total_bwd_pkts) if total_bwd_pkts > 0 else 0

        avg_pkt_size = (
            sum(flow["packet_sizes"]) / len(flow["packet_sizes"])
            if flow["packet_sizes"] else 0
        )

        pkt_size_std = (
            np.std(flow["packet_sizes"])
            if flow["packet_sizes"] else 0
        )
        min_pkt_len = min(flow["packet_sizes"]) if flow["packet_sizes"] else 0
        max_pkt_len = max(flow["packet_sizes"]) if flow["packet_sizes"] else 0

        timestamps = flow["packet_timestamps"]

        if len(timestamps) >= 2:
            iats = [
                t2 - t1
                for t1, t2 in zip(timestamps[:-1], timestamps[1:])
            ]
            flow_iat_mean = np.mean(iats)
            flow_iat_max = np.max(iats)
            flow_iat_min = np.min(iats)
        else:
            flow_iat_mean = 0
            flow_iat_max = 0
            flow_iat_min = 0

        label = flow_labels.get(fk, "Misc")
        if label == "BruteForce":
            if avg_pkt_size < AVG_PKT_SIZE_THRESHOLD: 
                log_alert(
                    flow["last_seen"],
                    "BruteForce",
                    fk[0],
                    fk[1],
                    fk[2],
                    flow["protocol"],
                    f"Avg size={avg_pkt_size:.2f}, pkts={total_fwd_pkts}"
                )
                flow_labels[fk] = "BruteForce"
            else:
                flow_labels[fk] = "Misc"
                print("ML Prediction: Not enough Force")

        # -------------------------
        # Label Expired Flow
        # -------------------------

        mapped_label = label_expired_flow(fk, flow)
        connections_per_minute = flow.get("connections_per_minute", 0)
        # -------------------------
        # Write ML CSV
        # -------------------------

        ml_writer.writerow([
            fk[2],                  # Destination Port
            duration,
            total_fwd_pkts,
            total_bwd_pkts,
            total_fwd_bytes,
            total_bwd_bytes,
            flow_bytes_per_s,
            flow_pkts_per_s,
            fwd_pkt_len_mean,
            bwd_pkt_len_mean,
            avg_pkt_size,
            pkt_size_std,
            min_pkt_len,
            max_pkt_len,
            flow_iat_mean,
            flow_iat_max,
            flow_iat_min,
            connections_per_minute,
            mapped_label
        ])
        ml_csv.flush()
        feature_vector = [
            fk[2],                 # Destination Port
            duration,
            total_fwd_pkts,
            total_bwd_pkts,
            total_fwd_bytes,
            total_bwd_bytes,
            flow_bytes_per_s,
            flow_pkts_per_s,
            fwd_pkt_len_mean,
            bwd_pkt_len_mean,
            avg_pkt_size,
            pkt_size_std,
            min_pkt_len,
            max_pkt_len,
            flow_iat_mean,
            flow_iat_max,
            flow_iat_min,
            connections_per_minute,
        ]

        ml_prediction = clf.predict([feature_vector])[0]
        pred_label = label_mapping.get(ml_prediction, "Unknown")
        print(f"ML Prediction: {pred_label}")

        # -------------------------
        # Cleanup
        # -------------------------

        del flows[fk]
        if fk in flow_labels:
            del flow_labels[fk]

# -----------------------------
# Process Each Packet
# -----------------------------

def process_packet(pkt):
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        length = int(pkt.length)
        protocol = pkt.transport_layer
        timestamp = float(pkt.sniff_timestamp)
        dst_port = int(pkt[protocol].dstport) if protocol in pkt else 0
    except AttributeError:
        return

    flow_key = (src_ip, dst_ip, dst_port, protocol)

    if flows[flow_key]["first_seen"] is None:
        flows[flow_key]["first_seen"] = timestamp

    flows[flow_key]["last_seen"] = timestamp
    flows[flow_key]["duration"] = flows[flow_key]["last_seen"] - flows[flow_key]["first_seen"]
    flows[flow_key]["protocol"] = protocol
    flows[flow_key]["packet_sizes"].append(length)
    flows[flow_key]["packet_timestamps"].append(timestamp)

    if src_ip == flow_key[0]:
        flows[flow_key]["total_fwd_packets"] += 1
        flows[flow_key]["total_bytes_fwd"] += length
    else:
        flows[flow_key]["total_bwd_packets"] += 1
        flows[flow_key]["total_bytes_bwd"] += length

    # Behavioral detection
    check_port_scan(src_ip, dst_port, timestamp)
    check_brute_force(src_ip, dst_ip, dst_port, timestamp)
    check_ddos(dst_ip, length, timestamp)
    check_exfil(src_ip, length, timestamp)
    check_connection_rate(src_ip, timestamp, flow_key)

    expire_flows(timestamp)
    expire_old_alerts(timestamp)

# -----------------------------
# Main Sniffer Loop
# -----------------------------

if __name__ == "__main__":
    cap = pyshark.LiveCapture(interface='en0')

    for pkt in cap.sniff_continuously():
        process_packet(pkt)

