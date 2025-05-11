import time
from sdk import SecureChannelSDK
from datetime import datetime

def client2_test():
    print("\n=== Starting Client 2 Test ===")

    try:
        client2 = SecureChannelSDK(
            client_name="Client-2",
            client_id="client_5678",
            identity_dir="client2"
        )


        print(f"[DEBUG] Client 2 initialized at {datetime.now().isoformat()}")

        print("\n[Phase 1][{0}] Connecting to KDC...".format(datetime.now().strftime('%H:%M:%S')))
        client2.connect_to_kdc()
        print("[DEBUG] Key exchange completed successfully")

        status = client2.identity_manager.check_identity_expiration()
        print(f"[DEBUG] Registration status: {status}")

        print("\n[Phase 2][{0}] Starting peer listener...".format(datetime.now().strftime('%H:%M:%S')))
        client2.listen_for_peers(port=6002)

        print("\n[Phase 3][{0}] Authorizing Client-1...".format(datetime.now().strftime('%H:%M:%S')))
        client2.identity_manager.update_authorized_peers(["client_f73a08ce"])

        print("\n[Phase 4][{0}] Waiting for PSK...".format(datetime.now().strftime('%H:%M:%S')))
        psk = client2.receive_shared_psk("client_1234")
        print(f"[SUCCESS] PSK received at {datetime.now().isoformat()}")

    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        print(f"Error occurred at: {datetime.now().isoformat()}")
    finally:
        print("\n=== Client 2 Test Complete ===")

if __name__ == "__main__":
    client2_test()
    while True:
        time.sleep(1)
