import time
from sdk import SecureChannelSDK
from datetime import datetime

def client1_test():
    print("\n=== Starting Client 2 Test ===")
    
    try:
        # Initialize client with specific ID for testing
        client1 = SecureChannelSDK(client_name="Client-2", client_id="client_999")
        print(f"[DEBUG] Client 1 initialized at {datetime.now().isoformat()}")
        
        # Phase 1: Connect to KDC
        print("\n[Phase 1][{0}] Connecting to KDC...".format(datetime.now().strftime('%H:%M:%S')))
        client1.connect_to_kdc()
        print("[DEBUG] Key exchange completed successfully")
        
        # Check registration status
        status = client1.identity_manager.check_identity_expiration()
        print(f"[DEBUG] Registration status: {status}")
        
        # Start listening for peer connections
        print("\n[Phase 2][{0}] Starting peer listener...".format(datetime.now().strftime('%H:%M:%S')))
        client1.listen_for_peers(port=6001)
        
        # Authorize Client 2
        print("\n[Phase 3][{0}] Authorizing Client-2...".format(datetime.now().strftime('%H:%M:%S')))
        client1.identity_manager.update_authorized_peers(["client_5678"])
        
        # Generate and distribute PSK
        print("\n[Phase 4][{0}] Generating PSK...".format(datetime.now().strftime('%H:%M:%S')))
        psk = client1.generate_and_distribute_shared_psk("client_5678")
        print(f"[DEBUG] PSK generated at {datetime.now().isoformat()}")
        
        # Attempt connection
        print("\n[Phase 5][{0}] Connecting to Client-2...".format(datetime.now().strftime('%H:%M:%S')))
        conn = client1.connect_to_peer("client_5678", port=6002)
        conn.send(b"Hello from Client-1!")
        response = conn.recv(1024)
        print(f"[SUCCESS] Received: {response.decode()}")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        print(f"Error occurred at: {datetime.now().isoformat()}")
    finally:
        print("\n=== Client 1 Test Complete ===")

if __name__ == "__main__":
    client1_test()
    while True:
        time.sleep(1)

