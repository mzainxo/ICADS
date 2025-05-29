import time
import threading
import pickle
import pandas as pd
from datetime import datetime
import pexpect
from scapy.all import sniff, IP, TCP
from concurrent.futures import ThreadPoolExecutor
import subprocess
import psutil

from firebase_manager import log_stats

# Configuration
INTERFACE    = "eth0"
MODEL_PATH   = "/etc/suricata/model/rf_model_combined.pkl"
FLOW_TIMEOUT = 3.0

# Load model
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Thread-safe structures
blacklisted_ips = set()
flows = {}
hping_sources = set()
data_lock = threading.Lock()
blacklist_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=6)

# Counters and status variables
total_packets = 0
hping3_packets = 0
classified_ddos_packets = 0
ddos_hping_packets = 0
system_status = "NORMAL"
last_ddos_time = None
last_normal_time = datetime.now().isoformat()
current_target_ip = None
current_src_ip = None
global ssid


def add_ip_to_blacklist(ip):
    with data_lock:
        if ip in blacklisted_ips:
            print(f"[BLACKLIST] {ip} already blacklisted. Skipping.")
            return
        blacklisted_ips.add(ip)

    cmds = [
        f"sudo suricatasc -c 'dataset-add blacklist ip {ip}'",
        "sudo suricatasc -c 'reload-rules'"
    ]

    with blacklist_lock:
        try:
            for cmd in cmds:
                pexpect.run(cmd)
            print(f"[BLACKLIST] Added {ip}")
        except Exception as e:
            print(f"[ERROR] Blacklisting {ip}: {e}")

def make_features(stat):
    avg_pkt_size = stat['total_bytes'] / stat['pkt_count'] if stat['pkt_count'] > 0 else 0
    return {
        'Average Packet Size':        avg_pkt_size,
        'Bwd Header Length':          stat.get('bwd_header_len', 0),
        'Destination Port':           stat['dst_port'],
        'Fwd Header Length':          stat.get('fwd_header_len', 0),
        'Protocol':                   stat['proto'],
        'Source Port':                stat['src_port'],
        'Total Backward Packets':     stat['bwd_pkts'],
        'Total Fwd Packets':          stat['fwd_pkts'],
        'Total Length of Bwd Packets': stat.get('bwd_total_bytes', 0),
        'Total Length of Fwd Packets': stat.get('fwd_total_bytes', 0),
    }

def classify_flow(st):
    global classified_ddos_packets, ddos_hping_packets

    feats = make_features(st)
    df = pd.DataFrame([feats])
    pred = model.predict(df)[0]

    if pred == 1:
        with data_lock:
            classified_ddos_packets += st['pkt_count']
            if st['is_hping']:
                ddos_hping_packets += st['pkt_count']
        print(f"[{datetime.now()}] 🚨 DDoS detected from {st['src_ip']}")
        add_ip_to_blacklist(st['src_ip'])
    else:
        print(f"[{datetime.now()}] ✅ Benign flow: {st['src_ip']} -> {st['dst_ip']}")

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def flow_collector(pkt):
    global total_packets, hping3_packets

    if not IP in pkt:
        return

    ip = pkt[IP]
    proto = ip.proto
    sport = getattr(pkt, 'sport', 0)
    dport = getattr(pkt, 'dport', 0)
    key = (ip.src, ip.dst, sport, dport, proto)
    ts = pkt.time
    size = len(pkt)
    ttl = ip.ttl

    is_hping = ttl == 111
    direction = 'fwd' if ip.src == key[0] else 'bwd'

    with data_lock:
        total_packets += 1
        if is_hping:
            hping3_packets += 1
            hping_sources.add(ip.src)

        if key not in flows:
            flows[key] = {
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'src_port': sport,
                'dst_port': dport,
                'proto': proto,
                'start': ts,
                'last_seen': ts,
                'pkt_count': 0,
                'total_bytes': 0,
                'fwd_pkts': 0,
                'bwd_pkts': 0,
                'fwd_header_len': 0,
                'bwd_header_len': 0,
                'fwd_total_bytes': 0,
                'bwd_total_bytes': 0,
                'is_hping': is_hping
            }

        st = flows[key]
        st['pkt_count'] += 1
        st['total_bytes'] += size
        st['last_seen'] = ts

        if direction == 'fwd':
            st['fwd_pkts'] += 1
            st['fwd_total_bytes'] += size
            if TCP in pkt:
                st['fwd_header_len'] += pkt[TCP].dataofs * 4
        else:
            st['bwd_pkts'] += 1
            st['bwd_total_bytes'] += size
            if TCP in pkt:
                st['bwd_header_len'] += pkt[TCP].dataofs * 4

def flow_timeout_checker():
    while True:
        now = time.time()
        expired = []
        with data_lock:
            for key, st in list(flows.items()):
                if now - st['last_seen'] > FLOW_TIMEOUT:
                    expired.append((key, flows.pop(key)))

        for key, st in expired:
            executor.submit(classify_flow, st)

        time.sleep(1)

def stats_printer():
    global system_status, last_ddos_time, last_normal_time, current_target_ip, target_ip, src_ip, current_src_ip, ssid

    while True:
        with data_lock:
            current_total = total_packets
            current_hping = hping3_packets
            current_ddos = classified_ddos_packets if classified_ddos_packets > 50 else 0
            current_ddos_hping = ddos_hping_packets
            current_benign_hping = current_hping - current_ddos_hping if current_hping > 0 else 0
            current_benign = current_total - current_hping
            active_hping = False
            
            for st in flows.values():
                if st['is_hping']:
                    active_hping = True
                    target_ip = st['dst_ip']
                    src_ip = st['src_ip']

            new_status = "DDoS" if active_hping else "Normal"
            now = datetime.now().isoformat()

            if new_status != system_status:
                print(f"[STATUS CHANGE] {system_status} -> {new_status} at {now}")
                
                if new_status == "DDoS":
                    last_ddos_time = now
                    current_target_ip = target_ip
                    current_src_ip = src_ip
                else:
                    last_normal_time = now
                
                system_status = new_status

        try:
            accuracy = current_ddos_hping / current_hping if current_hping > 0 else 0
        except ZeroDivisionError:
            accuracy = 0.0
        cpu_usage = get_cpu_usage()
        
        stats = {
            "total_packets": int(current_total),
            "ddos_packets": int(current_ddos),
            "benign_hping": int(current_benign_hping),
            "benign": int(current_benign),
            "simulated_hping": int(current_hping),
            "accuracy": float(accuracy),
            "system_status": system_status,
            "cpu_usage": float(cpu_usage),
            "last_ddos_time": last_ddos_time,
            "last_normal_time": last_normal_time,
            "source_ip": current_src_ip if current_src_ip != None else "0.0.0.0",
            "destination_ip": current_target_ip if current_target_ip != None else "0.0.0.0"
        }

        print(f"[STATS] Status: {system_status} | "
              f"Last DDoS: {last_ddos_time or 'Never'} | "
              f"Last Normal: {last_normal_time} | "
              f"Source: {current_src_ip or '0.0.0.0'} | "
              f"Target: {current_target_ip or '0.0.0.0'} | "
              f"CPU: {cpu_usage}%"
              f"| Total: {current_total} | DDoS: {current_ddos} "
              f"| Benign (HPING3): {current_benign_hping} | Benign: {current_benign}"
              f"| Simulated (HPING3): {current_hping} | Accuracy: {accuracy:.2f}")

        try:
            log_stats(stats)
        except Exception as e:
            print(f"[ERROR] Firebase logging: {e}")

        time.sleep(0.5)

if __name__ == '__main__':
    print(f"Starting packet capture on {INTERFACE}...")
    threading.Thread(target=flow_timeout_checker, daemon=True).start()
    threading.Thread(target=stats_printer, daemon=True).start()
    sniff(iface=INTERFACE, prn=flow_collector, store=False)