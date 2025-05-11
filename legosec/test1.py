import time
import json
import sqlite3
from datetime import datetime
from sdk import SecureChannelSDK

def client2_test():
    print("\n=== Starting Client 2 Test ===")
    
    try:
        # Initialize client with specific ID for testing
        client2 = SecureChannelSDK(client_name="Client-2", client_id="client_5678")
        print(f"[DEBUG] Client 2 initialized at {datetime.now().isoformat()}")
        
        # Phase 1: Connect to KDC
        print("\n[Phase 1][{0}] Connecting to KDC...".format(datetime.now().strftime('%H:%M:%S')))
        client2.connect_to_kdc()
        print("[DEBUG] Key exchange completed successfully")
        
        # Check registration status
        identity = client2.identity_manager.load_identity()
        print(f"[DEBUG] Registration status: {'Registered' if identity else 'Not registered'}")
        
        # Start listening for peer connections
        print("\n[Phase 2][{0}] Starting peer listener...".format(datetime.now().strftime('%H:%M:%S')))
        client2.listen_for_peers(port=6002)
        
        # Authorize Client 1
        print("\n[Phase 3][{0}] Authorizing Client-1...".format(datetime.now().strftime('%H:%M:%S')))
        with sqlite3.connect(client2.identity_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE clients SET authorized_peers = ?
                WHERE client_id = ?
            """, (json.dumps(["client_1234"]), "client_5678"))
            conn.commit()
        
        # Wait for PSK
        print("\n[Phase 4][{0}] Waiting for PSK...".format(datetime.now().strftime('%H:%M:%S')))
        start_time = time.time()
        while time.time() - start_time < 30:  # Wait up to 30 seconds
            try:
                psk = client2.receive_shared_psk("client_1234")
                print(f"[SUCCESS] PSK received at {datetime.now().isoformat()}")
                break
            except Exception as e:
                if time.time() - start_time >= 30:
                    print("[ERROR] Timed out waiting for PSK")
                    break
                time.sleep(1)
        
        # Keep running to handle incoming connections
        print("\n[Phase 5][{0}] Ready for incoming connections...".format(datetime.now().strftime('%H:%M:%S')))
        print(f"[INFO] Listening on port 6002 for incoming connections...")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        print(f"Error occurred at: {datetime.now().isoformat()}")
    finally:
        print("\n=== Client 2 Test Complete ===")

if __name__ == "__main__":
    client2_test()
    while True:
        time.sleep(1)