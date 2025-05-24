from legosec import (
    connect_to_kdc,
    start_peer_listener,
    connect_to_peer,
    send_message_to_peer,
    get_identity_status,
    list_authorized_peers,
    add_authorize_peer,
)

import time

# === EXAMPLE 1 ===
# First-time setup + registration
def example_1_first_time_setup():
    print("\n[EXAMPLE 1] First-Time Setup and Registration")
    sdk = connect_to_kdc(client_name="ClientAlice")
    print(f"Identity Status: {get_identity_status(sdk)}")


# === EXAMPLE 2 ===
# Listening for incoming secure connections (non-blocking)
def example_2_start_listening():
    print("\n[EXAMPLE 2] Start Listening for Secure Connections")
    sdk = connect_to_kdc(client_name="ClientListener")
    start_peer_listener(sdk, port=6000)
    print("Peer listener is running in the background...")
    time.sleep(10)  # Keep alive for a short while to simulate running service


# === EXAMPLE 3 ===
# Sending a secure message to a peer (who is already listening)
def example_3_send_secure_message():
    print("\n[EXAMPLE 3] Send Secure Message to Peer")
    sdk = connect_to_kdc(client_name="ClientSender")
    conn = connect_to_peer(sdk, peer_id="client_listener_id", port=6000)
    send_message_to_peer(conn, "Hello securely from ClientSender!")


# === EXAMPLE 4 ===
# Checking identity expiration and authorized peers
def example_4_check_identity_and_peers():
    print("\n[EXAMPLE 4] Identity & Authorized Peers Check")
    sdk = connect_to_kdc(client_name="ClientCheck")
    status = get_identity_status(sdk)
    print(f"Identity status: {status}")

    peers = list_authorized_peers(sdk)
    print(f"Authorized peers: {peers}")


# === EXAMPLE 5 ===
# Full client lifecycle: setup → listen → connect → send → close
def example_5_full_lifecycle():
    print("\n[EXAMPLE 5] Full Secure Communication Lifecycle")
    sdk1 = connect_to_kdc(client_name="ClientA")
    sdk2 = connect_to_kdc(client_name="ClientB")

    # Authorize ClientA inside ClientB
    add_authorize_peer(sdk2, sdk1.client_id)

    start_peer_listener(sdk2, port=6001)
    time.sleep(1)

    conn = connect_to_peer(sdk1, peer_id=sdk2.client_id, port=6001)
    send_message_to_peer(conn, "Secure message from A to B")



if __name__ == "__main__":
    print("\n===== LegoSec SDK Usage Examples =====")
    try:
        # example_1_first_time_setup()
        # example_2_start_listening()
        # example_3_send_secure_message()
        # example_4_check_identity_and_peers()
        example_5_full_lifecycle()
    except Exception as e:
        print(f"\n[ERROR] Something went wrong during execution: {e}")
