import firebase_admin
from firebase_admin import credentials, db

# --- Update these paths and URLs ---
FIREBASE_KEY_PATH = "/home/kali/Desktop/ICADS/src/serviceAccountKey.json"  
DB_URL = "https://icads-fyp-default-rtdb.firebaseio.com"       

# Initialize Firebase app (only once)
cred = credentials.Certificate(FIREBASE_KEY_PATH)
firebase_admin.initialize_app(cred, {
    'databaseURL': DB_URL
})

def log_ddos_detection(flow_data):
    ref = db.reference("ddos_detections")
    ref.push(flow_data)

def log_stats(stats):
    ref = db.reference("stats")
    ref.set(stats)
