import os
import json
import sqlite3
import socket
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from OpenSSL.SSL import Context, Connection, TLSv1_2_METHOD
from openssl_psk import patch_context

patch_context()

class SecureChannelSDK:
    def __init__(self, client_id=None, kdc_host='127.0.0.1', kdc_port=5000):
        self.client_id = client_id or f"client_{os.urandom(4).hex()}"
        self.kdc_host = kdc_host
        self.kdc_port = kdc_port
        self.psk = None
        self.identity_manager = IdentityManager(self.client_id)
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()

    def connect_to_kdc(self):
        """Establish secure connection with KDC and register/authenticate"""
        print(f"[{self.client_id}] Connecting to KDC...")
        
        # Phase 1: Key Exchange
        with socket.socket() as s:
            s.connect((self.kdc_host, self.kdc_port))
            
            # Step 1: Receive KDC's public key
            pub_key_data = s.recv(4096)
            kdc_pub_key = serialization.load_pem_public_key(pub_key_data)
            
            # Step 2: Generate and send our parameter
            our_param = os.urandom(32)
            encrypted_param = kdc_pub_key.encrypt(
                our_param,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            s.sendall(encrypted_param)
            
            # Step 3: Receive KDC's parameter
            kdc_param_enc = s.recv(4096)
            
            # Step 4: Derive symmetric key
            symmetric_key = self._derive_symmetric_key(our_param)
            kdc_param = self._decrypt_with_key(symmetric_key, kdc_param_enc)
            
            # Step 5: Calculate PSK
            self.psk = self._generate_psk(our_param, kdc_param)
        
        # Phase 2: Registration/Authentication
        if not self.identity_manager.is_registered():
            print(f"[{self.client_id}] Registering with KDC...")
            self.identity_manager.register_on_kdc(kdc_pub_key)
        else:
            print(f"[{self.client_id}] Authenticating with KDC...")
            identity = self.identity_manager.load_identity()
            if self.identity_manager.is_expired(identity):
                print(f"[{self.client_id}] Identity expired, renewing...")
                self.identity_manager.register_on_kdc(kdc_pub_key)
        
        print(f"[{self.client_id}] Secure connection established with KDC")

    def connect_to_peer(self, peer_id, host='127.0.0.1', port=6000):
        if not self.identity_manager.is_peer_authorized(peer_id):
            raise ValueError(f"Peer {peer_id} not authorized")

        peer_psk = self.psk
        ctx = Context(TLSv1_2_METHOD)
        ctx.set_cipher_list(b'PSK')
        ctx.set_psk_client_callback(lambda c, h: (self.client_id.encode(), peer_psk))

        sock = socket.socket()
        sock.connect((host, port))
        conn = Connection(ctx, sock)
        conn.set_connect_state()
        conn.do_handshake()
        return conn

    def listen_for_peers(self, port=6000):
        """Start listening for incoming P2P connections"""
        def handler():
            ctx = Context(TLSv1_2_METHOD)
            ctx.set_cipher_list(b'PSK')
            ctx.set_psk_server_callback(self._verify_peer)
            
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen()
                print(f"[{self.client_id}] Listening for peers on port {port}")
                
                while True:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self._handle_peer_connection,
                        args=(ctx, conn),
                        daemon=True
                    ).start()
        
        threading.Thread(target=handler, daemon=True).start()

    # In your SecureChannelSDK class
    def _verify_peer(self, conn, identity):
        """Verify peer identity and return PSK"""
        peer_id = identity.decode()
        print(f"[{self.client_id}] Incoming peer ID: {peer_id}")
        if self.identity_manager.is_peer_authorized(peer_id):
            print(f"[{self.client_id}] Authorized peer: {peer_id}")
            return self.psk  # Return our PSK which should match the peer's
        print(f"[{self.client_id}] Unauthorized peer: {peer_id}")
        return None

    def _handle_peer_connection(self, ctx, conn):
        """Handle incoming P2P connection"""
        try:
            ssl_conn = Connection(ctx, conn)
            ssl_conn.set_accept_state()
            ssl_conn.do_handshake()

            while True:
                data = ssl_conn.recv(1024)
                if not data:
                    break
                print(f"[{self.client_id}] Received from peer: {data.decode()}")
                ssl_conn.send(f"ACK from {self.client_id}".encode())
        except Exception as e:
            print(f"[{self.client_id}] Peer connection error: {e}")
        finally:
            conn.close()


    def _derive_symmetric_key(self, shared_secret):
        """Derive symmetric key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-channel-key',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def _encrypt_with_key(self, key, data):
        """Encrypt data with symmetric key"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def _decrypt_with_key(self, key, data):
        """Decrypt data with symmetric key"""
        iv, encrypted = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()

    def _generate_psk(self, client_param, kdc_param):
        """Generate PSK from parameters"""
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(client_param + kdc_param)
        return h.finalize()


class IdentityManager:
    def __init__(self, client_id, identity_dir=".", db_path="kdc_database.db"):
        self.client_id = client_id
        self.identity_path = Path(identity_dir) / f".{client_id}_identity.json"
        self.db_path = db_path

    def is_registered(self):
        return self.identity_path.exists()

    def load_identity(self):
        if self.is_registered():
            with open(self.identity_path, 'r') as f:
                return json.load(f)
        return None

    def is_expired(self, identity_data):
        expires_at = datetime.strptime(identity_data['expires_at'], '%Y-%m-%d %H:%M:%S')
        return datetime.now() > expires_at

    def store_identity(self, encrypted_secret, expires_at):
        data = {
            'client_id': self.client_id,
            'encrypted_secret': encrypted_secret.hex(),
            'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(self.identity_path, 'w') as f:
            json.dump(data, f)

    def register_on_kdc(self, kdc_public_key):
        secret = os.urandom(32)
        expires_at = datetime.now() + timedelta(days=30)

        encrypted_secret = kdc_public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    secret_id BLOB NOT NULL,
                    authorized_peers TEXT,
                    expires_at TIMESTAMP NOT NULL,
                    public_key BLOB
                )
            """)
            cursor.execute("""
                INSERT OR REPLACE INTO clients (client_id, secret_id, authorized_peers, expires_at, public_key)
                VALUES (?, ?, ?, ?, ?)
            """, (self.client_id, encrypted_secret, json.dumps([]), expires_at, None))
            conn.commit()

        self.store_identity(encrypted_secret, expires_at)
        print(f"[REGISTER] {self.client_id} registered and identity stored.")

    def authenticate_with_kdc(self, encrypted_secret):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT secret_id, expires_at FROM clients WHERE client_id = ?", (self.client_id,))
            result = cursor.fetchone()
            if not result:
                return False

            stored_secret, expires_at = result

        try:
            expires_at = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
            if datetime.now() > expires_at:
                return False

            return encrypted_secret == stored_secret
        except Exception:
            return False

    def get_authorized_peers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT authorized_peers FROM clients WHERE client_id = ?", (self.client_id,))
            result = cursor.fetchone()
            if result:
                return json.loads(result[0])
            return []

    def update_authorized_peers(self, peer_list):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE clients
                SET authorized_peers = ?
                WHERE client_id = ?
            """, (json.dumps(peer_list), self.client_id))
            conn.commit()
    def is_peer_authorized(self, peer_id):
        """Check if peer is authorized for this client"""
        authorized = self.get_authorized_peers()
        return peer_id in authorized