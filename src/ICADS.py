import time
import threading
import pickle
import pandas as pd
import ipaddress
from datetime import datetime
import pexpect
from scapy.all import sniff, IP, TCP, UDP, ICMP
from concurrent.futures import ThreadPoolExecutor

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
data_lock = threading.Lock()        # For flows and counters
blacklist_lock = threading.Lock()   # For Suricata commands
executor = ThreadPoolExecutor(max_workers=4)  # For classification tasks

# Counters
total_packets = 0
hping3_packets = 0
classified_ddos_packets = 0

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
    global classified_ddos_packets
    
    feats = make_features(st)
    df = pd.DataFrame([feats])
    pred = model.predict(df)[0]

    if pred == 1:
        with data_lock:
            classified_ddos_packets += st['pkt_count']
        print(f"[{datetime.now()}] 🚨 DDoS detected from {st['src_ip']}")
        add_ip_to_blacklist(st['src_ip'])
    else:
        print(f"[{datetime.now()}] ✅ Benign flow: {st['src_ip']} -> {st['dst_ip']}")

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

    # Pre-calculate values outside lock
    is_hping = ttl == 111
    direction = 'fwd' if ip.src == key[0] else 'bwd'

    with data_lock:
        total_packets += 1
        if is_hping:
            hping3_packets += 1

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
    while True:
        with data_lock:
            current_total = total_packets 
            current_hping = hping3_packets
            current_ddos = classified_ddos_packets
            current_benign_hping = current_hping - current_ddos
            current_benign = current_total - current_hping

        try:
            accuracy = current_ddos / current_hping if current_hping > 0 else 0
        except ZeroDivisionError:
            accuracy = 0.0

        print(f"[STATS] Total: {current_total} | DDoS: {current_ddos} "
              f"| Benign (HPING3): {current_benign_hping} | Benign: {current_benign}"
              f"| Simulated (HPING3): {current_hping} | Accuracy: {accuracy:.2f}")
        time.sleep(5)

if __name__ == '__main__':
    print(f"Starting packet capture on {INTERFACE}...")
    threading.Thread(target=flow_timeout_checker, daemon=True).start()
    threading.Thread(target=stats_printer, daemon=True).start()
    sniff(iface=INTERFACE, prn=flow_collector, store=False)