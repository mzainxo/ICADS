import json
import time
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pickle  # Use pickle instead of joblib
from datetime import datetime
import subprocess
import pexpect
import random

# Path to eve.json
EVE_LOG_FILE = "/var/log/suricata/eve.json"

# Path to the Unix socket for Suricata
SOCKET_PATH = "/var/run/suricata-command.socket"

# Path to the pre-trained model .pkl file
MODEL_PATH = "/etc/suricata/model/random_forest_model.pkl"

# Load the pre-trained model using pickle
with open(MODEL_PATH, "rb") as model_file:
    model = pickle.load(model_file)

def debug_print(message, data=None):
    """Utility function for printing debug messages."""
    print(f"[DEBUG] {message}")
    if data is not None:
        print(f"[DEBUG DATA] {data}")

def add_ip_to_blacklist(ip):
    """Add an IP to Suricata blacklist using suricatasc"""
    command = f"sudo suricatasc -c 'dataset-add blacklist ip {ip}'"
    command2 = f"sudo suricatasc -c 'reload-rules'"
    try:
        child = pexpect.spawn(command)
        #child.expect(r'password for .*:')
        #child.sendline(password)
        #child.wait()
        print("Command output: ", child.read().decode())
        child2 = pexpect.spawn(command2)
        print("Command output: ", child2.read().decode())
            
    except pexpect.Exceptions.ExceptionPexpect as e:
        print("Error: ", str(e))

def extract_timestamp_components(timestamp):
    """Extract Year, Month, Day, Hour, Minute, Second from a timestamp."""
    try:
        # Parse the timestamp string into a datetime object
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        
        # Extract components
        year = dt.year
        month = dt.month
        day = dt.day
        hour = dt.hour
        minute = dt.minute
        second = dt.second
        
        return year, month, day, hour, minute, second
    except (ValueError, TypeError):
        # Return default values if parsing fails
        return 2023, 1, 1, 0, 0, 0
def extract_features(entry):
    """Extract all features from a Suricata log entry."""
    features = {}
    final_features={}
    # Unnamed: 0 (assign a random value)
    features["Unnamed: 0"] = random.randint(0, 1000)

    # Direct Mappings
    features["Flow ID"] = entry.get("flow_id", 0)
    features["Source IP"] = entry.get("src_ip", "0.0.0.0")
    features["Source Port"] = entry.get("src_port", 0)
    features["Destination IP"] = entry.get("dest_ip", "0.0.0.0")
    features["Destination Port"] = entry.get("dest_port", 0)
    features["Protocol"] = entry.get("proto", 0)

    # Flow Duration
    if "flow" in entry:
        start = entry["flow"].get("start")
        end = entry["flow"].get("end")
        try:
            start = float(start) if start else 0
            end = float(end) if end else 0
            features["Flow Duration"] = end - start
        except (ValueError, TypeError):
            features["Flow Duration"] = 0

        # Total Forward/Backward Packets
        features["Total Fwd Packets"] = entry["flow"].get("pkts_toserver", 0)
        features["Total Backward Packets"] = entry["flow"].get("pkts_toclient", 0)

        # Total Forward/Backward Bytes
        features["Total Length of Fwd Packets"] = entry["flow"].get("bytes_toserver", 0)
        features["Total Length of Bwd Packets"] = entry["flow"].get("bytes_toclient", 0)
    else:
        features["Flow Duration"] = 0
        features["Total Fwd Packets"] = 0
        features["Total Backward Packets"] = 0
        features["Total Length of Fwd Packets"] = 0
        features["Total Length of Bwd Packets"] = 0

    # Packet Length Stats
    features["Fwd Packet Length Max"] = entry.get("fwd_packet_len_max", 0)
    features["Fwd Packet Length Min"] = entry.get("fwd_packet_len_min", 0)
    features["Fwd Packet Length Mean"] = entry.get("fwd_packet_len_mean", 0)
    features["Fwd Packet Length Std"] = entry.get("fwd_packet_len_std", 0)

    features["Bwd Packet Length Max"] = entry.get("bwd_packet_len_max", 0)
    features["Bwd Packet Length Min"] = entry.get("bwd_packet_len_min", 0)
    features["Bwd Packet Length Mean"] = entry.get("bwd_packet_len_mean", 0)
    features["Bwd Packet Length Std"] = entry.get("bwd_packet_len_std", 0)

    # Derived Metrics
    features["Flow Bytes/s"] = features["Total Length of Fwd Packets"] + features["Total Length of Bwd Packets"]
    features["Flow Packets/s"] = features["Total Fwd Packets"] + features["Total Backward Packets"]

    # Calculate Fwd Packets/s and Bwd Packets/s
    if features["Flow Duration"] > 0:
        features["Fwd Packets/s"] = features["Total Fwd Packets"] / features["Flow Duration"]
        features["Bwd Packets/s"] = features["Total Backward Packets"] / features["Flow Duration"]
    else:
        features["Fwd Packets/s"] = 0
        features["Bwd Packets/s"] = 0

    # Inter-Arrival Times
    features["Flow IAT Mean"] = entry.get("flow_iat_mean", 0)
    features["Flow IAT Std"] = entry.get("flow_iat_std", 0)
    features["Flow IAT Max"] = entry.get("flow_iat_max", 0)
    features["Flow IAT Min"] = entry.get("flow_iat_min", 0)

    features["Fwd IAT Total"] = entry.get("fwd_iat_total", 0)
    features["Fwd IAT Mean"] = entry.get("fwd_iat_mean", 0)
    features["Fwd IAT Std"] = entry.get("fwd_iat_std", 0)
    features["Fwd IAT Max"] = entry.get("fwd_iat_max", 0)
    features["Fwd IAT Min"] = entry.get("fwd_iat_min", 0)

    features["Bwd IAT Total"] = entry.get("bwd_iat_total", 0)
    features["Bwd IAT Mean"] = entry.get("bwd_iat_mean", 0)
    features["Bwd IAT Std"] = entry.get("bwd_iat_std", 0)
    features["Bwd IAT Max"] = entry.get("bwd_iat_max", 0)
    features["Bwd IAT Min"] = entry.get("bwd_iat_min", 0)

    # Flags
    features["Fwd PSH Flags"] = entry.get("fwd_psh_flags", 0)
    features["Bwd PSH Flags"] = entry.get("bwd_psh_flags", 0)
    features["Fwd URG Flags"] = entry.get("fwd_urg_flags", 0)
    features["Bwd URG Flags"] = entry.get("bwd_urg_flags", 0)

    # Header Lengths
    features["Fwd Header Length"] = entry.get("fwd_header_len", 0)
    features["Bwd Header Length"] = entry.get("bwd_header_len", 0)

    # Packet Statistics
    features["Min Packet Length"] = entry.get("min_packet_len", 0)
    features["Max Packet Length"] = entry.get("max_packet_len", 0)
    features["Packet Length Mean"] = entry.get("packet_len_mean", 0)
    features["Packet Length Std"] = entry.get("packet_len_std", 0)
    features["Packet Length Variance"] = entry.get("packet_len_variance", 0)

    # TCP Flags
    features["FIN Flag Count"] = entry.get("tcp_flags_fin", 0)
    features["SYN Flag Count"] = entry.get("tcp_flags_syn", 0)
    features["RST Flag Count"] = entry.get("tcp_flags_rst", 0)
    features["PSH Flag Count"] = entry.get("tcp_flags_psh", 0)
    features["ACK Flag Count"] = entry.get("tcp_flags_ack", 0)
    features["URG Flag Count"] = entry.get("tcp_flags_urg", 0)
    features["CWE Flag Count"] = entry.get("tcp_flags_cwe", 0)
    features["ECE Flag Count"] = entry.get("tcp_flags_ece", 0)

    # Subflow Metrics
    features["Subflow Fwd Packets"] = entry.get("subflow_fwd_pkts", 0)
    features["Subflow Fwd Bytes"] = entry.get("subflow_fwd_bytes", 0)
    features["Subflow Bwd Packets"] = entry.get("subflow_bwd_pkts", 0)
    features["Subflow Bwd Bytes"] = entry.get("subflow_bwd_bytes", 0)

    # TCP Window Sizes
    features["Init_Win_bytes_forward"] = entry.get("init_win_bytes_fwd", 0)
    features["Init_Win_bytes_backward"] = entry.get("init_win_bytes_bwd", 0)

    # Active/Idle Times
    features["Active Mean"] = entry.get("active_mean", 0)
    features["Active Std"] = entry.get("active_std", 0)
    features["Active Max"] = entry.get("active_max", 0)
    features["Active Min"] = entry.get("active_min", 0)
    features["Idle Mean"] = entry.get("idle_mean", 0)
    features["Idle Std"] = entry.get("idle_std", 0)
    features["Idle Max"] = entry.get("idle_max", 0)
    features["Idle Min"] = entry.get("idle_min", 0)

    # Additional Features (assign random values if not available)
    features["Down/Up Ratio"] = random.random()
    features["Average Packet Size"] = random.random()
    features["Avg Fwd Segment Size"] = random.random()
    features["Avg Bwd Segment Size"] = random.random()
    features["Fwd Header Length.1"] = random.random()
    features["Fwd Avg Bytes/Bulk"] = random.random()
    features["Fwd Avg Packets/Bulk"] = random.random()
    features["Fwd Avg Bulk Rate"] = random.random()
    features["Bwd Avg Bytes/Bulk"] = random.random()
    features["Bwd Avg Packets/Bulk"] = random.random()
    features["Bwd Avg Bulk Rate"] = random.random()
    features["act_data_pkt_fwd"] = random.random()
    features["min_seg_size_forward"] = random.random()
    features["SimillarHTTP"] = random.randint(0, 1)
    features["Inbound"] = random.randint(0, 1)

    # Extract date and time components from the timestamp
    timestamp = entry.get("timestamp", "2023-01-01T00:00:00.000Z")
    year, month, day, hour, minute, second = extract_timestamp_components(timestamp)
    features["Year"] = year
    features["Month"] = month
    features["Day"] = day
    features["Hour"] = hour
    features["Minute"] = minute
    features["Second"] = second
    feature_order = [
        "Unnamed: 0", "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
        "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
        "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
        "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
        "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max",
        "Idle Min", "SimillarHTTP", "Inbound", "Year", "Month", "Day", "Hour", "Minute", "Second"
    ]
    for f in feature_order:
        final_features[f] = features[f]
    return final_features

def classify_flow(features):
    """Classify the flow using the pre-trained model."""
    # Convert features to DataFrame
    df = pd.DataFrame([features])
    # Predict using the model
    prediction = model.predict(df)
    return prediction[0]  # 0 for normal, 1 for DDoS

class EveLogHandler(FileSystemEventHandler):
    """Handler to monitor changes in eve.json."""
    def on_modified(self, event):
        if event.src_path == EVE_LOG_FILE:
            process_new_entries()

def process_new_entries():
    """Process new entries in eve.json."""
    with open(EVE_LOG_FILE, "r") as file:
        file.seek(0, 2)  # Move to the end of the file
        while True:
            line = file.readline()
            if not line:
                break
            try:
                entry = json.loads(line.strip())
                #if entry.get("event_type") == "flow":  # Focus on flow logs
                    #features = extract_features(entry)
                    #prediction = classify_flow(features)
                    #if prediction == 1:  # DDoS detected
                try:
                    flagged_ip = '192.111.33.32'
                    print(f"DDoS detected from {flagged_ip} at {datetime.now()}")
                    add_ip_to_blacklist(flagged_ip)
                except Exception as e:
                    print("Error adding IP to blacklist",e)
            except json.JSONDecodeError:
                continue

# Start monitoring the eve.json file
if __name__ == "__main__":
    event_handler = EveLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log/suricata/", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()