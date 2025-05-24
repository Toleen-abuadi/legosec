import unittest
import time
import os
import socket
from legosec import (
    connect_to_kdc,
    start_peer_listener,
    connect_to_peer,
    send_message_to_peer,
    get_identity_status,
    list_authorized_peers
)

def find_free_port():
    """Find a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 0))
        return s.getsockname()[1]

class TestLegoSecSDK(unittest.TestCase):
    def setUp(self):
        self.port = find_free_port()
        self.sdk_a = connect_to_kdc("TestClientA", identity_dir="./test_id_a")
        self.sdk_b = connect_to_kdc("TestClientB", identity_dir="./test_id_b")
        
        # Setup PSK before starting listener
        self.sdk_a.generate_and_distribute_shared_psk(self.sdk_b.client_id)
        self.sdk_b.generate_and_distribute_shared_psk(self.sdk_a.client_id)
        
        start_peer_listener(self.sdk_b, port=self.port)
        
        # Wait for listener to be ready
        for _ in range(10):
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=1):
                    break
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(0.5)
        else:
            self.fail("Peer listener did not start in time")

    def tearDown(self):
        # Let connections and threads settle
        time.sleep(0.5)
        
        # Close all connections
        if hasattr(self, 'sdk_a'):
            self.sdk_a._close_all_connections()
        if hasattr(self, 'sdk_b'):
            self.sdk_b._close_all_connections()
        
        # Clean up identity files
        for path in ["./test_id_a", "./test_id_b"]:
            if os.path.exists(path):
                for f in os.listdir(path):
                    if f.endswith(".json"):
                        os.remove(os.path.join(path, f))
                os.rmdir(path)

    def test_identity_registration(self):
        """Test that identity was created and is valid"""
        status = get_identity_status(self.sdk_a)
        self.assertTrue(status.startswith("valid") or status.startswith("expiring_soon"))

    def test_peer_authorization(self):
        """Test peer is not authorized by default"""
        peers = list_authorized_peers(self.sdk_a)
        self.assertIsInstance(peers, list)
        self.assertNotIn(self.sdk_b.client_id, peers)

    def test_secure_connection_establishment(self):
        """Test successful secure handshake with peer"""
        conn = None
        try:
            conn = connect_to_peer(self.sdk_a, self.sdk_b.client_id, port=self.port)
            self.assertIsNotNone(conn)
        finally:
            if conn:
                conn.close()

    def test_secure_message_exchange(self):
        """Test encrypted message send and response"""
        conn = None
        try:
            conn = connect_to_peer(self.sdk_a, self.sdk_b.client_id, port=self.port)
            conn.send(b"Hello from A")
            response = conn.recv(1024)
            self.assertIn(b"ACK", response)
        finally:
            if conn:
                conn.close()

    def test_auto_identity_renewal(self):
        """Test that expired identities are auto-renewed"""
        identity_file = self.sdk_a.identity_path
        with open(identity_file, "r") as f:
            data = f.read()
        
        # Expire the identity by manipulating the file
        data = data.replace("202", "2000")
        with open(identity_file, "w") as f:
            f.write(data)

        # Should auto-renew during re-connect
        sdk_fresh = connect_to_kdc("TestClientA", identity_dir="./test_id_a")
        status = get_identity_status(sdk_fresh)
        self.assertEqual(status, "valid")

    def test_peer_authorization_after_connection(self):
        """Test that peers are authorized after a successful connection"""
        conn = connect_to_peer(self.sdk_a, self.sdk_b.client_id, port=self.port)
        authorized_peers = list_authorized_peers(self.sdk_a)
        self.assertIn(self.sdk_b.client_id, authorized_peers)
        conn.close()

if __name__ == "__main__":
    print("\n🧪 Running LegoSec SDK Tests...\n")
    unittest.main(verbosity=2)
