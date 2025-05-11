import time
import os
import json
import uuid
from sdk import SecureChannelSDK
from datetime import datetime

def client1_test():
    print("\n=== Starting Client 1 Test ===")

    try:
        # Dynamically assign identity directory
        identity_dir = os.environ.get("CLIENT1_DIR", "client1")
        os.makedirs(identity_dir, exist_ok=True)

        # Attempt to discover existing identity
        existing_id = None
        for filename in os.listdir(identity_dir):
            if filename.endswith("_identity.json"):
                with open(os.path.join(identity_dir, filename), "r") as f:
                    data = json.load(f)
                    existing_id = data.get("client_id")
                    break

        # Use existing client ID if found, otherwise generate a new one
        client_id = existing_id or os.environ.get("CLIENT1_ID", "client_" + uuid.uuid4().hex[:8])
        identity_file = os.path.join(identity_dir, f".{client_id}_identity.json")
        identity_exists = os.path.isfile(identity_file)

        client1 = SecureChannelSDK(client_name="Client-1", client_id=client_id, identity_dir=identity_dir)
        print(f"[DEBUG] Client 1 initialized at {datetime.now().isoformat()} with ID {client_id}")

        # Phase 1: Connect to KDC (skip registration if identity exists)
        print("\n[Phase 1][{0}] Connecting to KDC...".format(datetime.now().strftime('%H:%M:%S')))
        if identity_exists:
            print(f"[DEBUG] Using existing identity file: {identity_file}")
        client1.connect_to_kdc()
        print("[DEBUG] Key exchange completed successfully")

        # Phase 2: Start peer listener
        print("\n[Phase 2][{0}] Starting peer listener...".format(datetime.now().strftime('%H:%M:%S')))
        client1.listen_for_peers(port=6001)

        # Phase 3: Authorize Client 2
        print("\n[Phase 3][{0}] Authorizing Client-2...".format(datetime.now().strftime('%H:%M:%S')))
        client1.identity_manager.update_authorized_peers(["client_5678"])

        # Phase 4: Generate and distribute PSK
        print("\n[Phase 4][{0}] Generating PSK...".format(datetime.now().strftime('%H:%M:%S')))
        psk = client1.generate_and_distribute_shared_psk("client_5678")
        print(f"[DEBUG] PSK generated at {datetime.now().isoformat()}")

        # Phase 5: Attempt connection
        print("\n[Phase 5][{0}] Connecting to Client-2...".format(datetime.now().strftime('%H:%M:%S')))
        conn = client1.connect_to_peer("client_5678", port=6002)
        conn.send(b"Hello from Client-1!")
        response = conn.recv(1024)
        if response:
            print(f"[SUCCESS] Received: {response.decode()}")
        else:
            print("[ERROR] No response received")

    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        print(f"Error occurred at: {datetime.now().isoformat()}")
    finally:
        print("\n=== Client 1 Test Complete ===")

if __name__ == "__main__":
    client1_test()
    while True:
        time.sleep(1)
