import firebase_admin
from firebase_admin import credentials, auth

# Path to your downloaded Firebase service account key JSON
FIREBASE_CRED = "/home/kali/Desktop/ICADS/src/serviceAccountKey.json"

def main():
    try:
        # Initialize Firebase Admin SDK with your credentials
        cred = credentials.Certificate(FIREBASE_CRED)
        firebase_admin.initialize_app(cred)
        print("[INFO] Firebase initialized successfully")

        # Replace with a real email registered in your Firebase project
        test_email = "mzainjed@gmail.com"

        # Try to fetch the user by email
        user = auth.get_user_by_email(test_email)
        print(f"[INFO] User found: UID={user.uid} Email={user.email}")

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
