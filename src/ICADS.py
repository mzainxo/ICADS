import time
import threading
import pickle
import pandas as pd
import ipaddress
from datetime import datetime
import pexpect
from scapy.all import sniff, IP, TCP, UDP

# Configuration
INTERFACE    = "eth0"
MODEL_PATH   = "/etc/suricata/model/rf_model_new.pkl"
FLOW_TIMEOUT = 3.0

# Load model
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Blacklist
def add_ip_to_blacklist(ip):
    cmd_add = f"sudo suricatasc -c 'dataset-add blacklist ip {ip}'"
    cmd_reload = "sudo suricatasc -c 'reload-rules'"
    try:
        child = pexpect.spawn(cmd_add)
        child.wait()
        print(f"[BLACKLIST] Added {ip}")
        reld = pexpect.spawn(cmd_reload)
        reld.wait()
    except Exception as e:
        print(f"[ERROR] Blacklisting {ip}: {e}")

# Flow table
flows = {}
lock  = threading.Lock()

# Feature Extraction
def make_features(stat):
    src_num = int(ipaddress.IPv4Address(stat['src_ip']))
    dst_num = int(ipaddress.IPv4Address(stat['dst_ip']))

    fwd_pkts = stat['fwd_pkts'] or 1
    bwd_pkts = stat['bwd_pkts'] or 1

    features = {
        'Source_IP_Num':              src_num,
        'Destination_IP_Num':         dst_num,
        'Destination Port':           stat['dst_port'],
        'Source Port':                stat['src_port'],
        'act_data_pkt_fwd':           stat['act_data_pkt_fwd'],
        'Inbound':                    1 if stat['src_ip'] != stat['my_ip'] else 0,
        'Init_Win_bytes_forward':     stat['init_win_bytes_fwd'],
        'Total Backward Packets':     bwd_pkts,
        'Fwd Header Length':          stat['fwd_header_len'],
        'Subflow Fwd Packets':        fwd_pkts,
    }
    return features

# Classification
def classify_and_blacklist(stat):
    feats = make_features(stat)
    df = pd.DataFrame([feats])
    pred = model.predict(df)[0]
    if pred == 1:
        print(f"[{datetime.now()}] DDoS detected from {stat['src_ip']}")
        add_ip_to_blacklist(stat['src_ip'])
    else:
        print(f"[{datetime.now()}] Benign flow: {stat['src_ip']} -> {stat['dst_ip']}")

# Packet Capture Callback
def flow_collector(pkt):
    if not IP in pkt:
        return

    ip = pkt[IP]
    proto = ip.proto
    sport = pkt.sport if hasattr(pkt, 'sport') else 0
    dport = pkt.dport if hasattr(pkt, 'dport') else 0

    key = (ip.src, ip.dst, sport, dport, proto)
    ts  = pkt.time
    size = len(pkt)

    with lock:
        st = flows.get(key)
        if not st:
            st = {
                'src_ip':             ip.src,
                'dst_ip':             ip.dst,
                'src_port':           sport,
                'dst_port':           dport,
                'proto':              proto,
                'start':              ts,
                'last_seen':          ts,
                'pkt_count':          0,
                'total_bytes':        0,
                'fwd_pkts':           0,
                'bwd_pkts':           0,
                'fwd_header_len':     0,
                'init_win_bytes_fwd': 8192,    # default if unknown
                'act_data_pkt_fwd':   0,
                'my_ip':              pkt[IP].src  # assuming traffic from us
            }
            flows[key] = st

        st['pkt_count']   += 1
        st['total_bytes'] += size
        st['last_seen']    = ts

        if ip.src == st['src_ip']:
            st['fwd_pkts'] += 1
            if TCP in pkt:
                st['fwd_header_len'] += pkt[TCP].dataofs * 4
                st['act_data_pkt_fwd'] += 1 if len(pkt[TCP].payload) > 0 else 0
        else:
            st['bwd_pkts'] += 1

# Flow expiration
def flow_timeout_checker():
    while True:
        now = time.time()
        expired = []
        with lock:
            for key, st in flows.items():
                if now - st['last_seen'] > FLOW_TIMEOUT:
                    expired.append(key)
            for key in expired:
                st = flows.pop(key)
                classify_and_blacklist(st)
        time.sleep(1)

# Start sniffing
if __name__ == '__main__':
    print(f"Starting packet capture on {INTERFACE}...")
    t = threading.Thread(target=flow_timeout_checker, daemon=True)
    t.start()
    sniff(iface=INTERFACE, prn=flow_collector, store=False)
