import socket
import threading
import os
import json
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class KDCServer:
    def __init__(self, host='0.0.0.0', port=5000, db_path='kdc_database.db'):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.private_key = self._generate_private_key()
        self.public_key = self.private_key.public_key()
        #self._init_database()
        self._running = False
        print(f"[KDC] Initialized with {self.private_key.key_size}-bit RSA key")

    def _generate_private_key(self):
        """Generate RSA private key for KDC"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )


    # def _init_database(self):
    #     """Initialize database tables"""
    #     with sqlite3.connect(self.db_path) as conn:
    #         cursor = conn.cursor()
    #         # Clients table
    #         cursor.execute("""
    #             CREATE TABLE IF NOT EXISTS clients (
    #                 client_id TEXT PRIMARY KEY,
    #                 client_name TEXT NOT NULL,
    #                 secret_id BLOB NOT NULL,
    #                 authorized_peers TEXT,
    #                 expires_at TIMESTAMP NOT NULL,
    #                 public_key BLOB,
    #                 last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    #             )
    #         """)
    #         # PSK exchange table
    #         cursor.execute("""
    #             CREATE TABLE IF NOT EXISTS psk_exchange (
    #                 from_id TEXT,
    #                 to_id TEXT,
    #                 shared_psk BLOB,
    #                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    #                 PRIMARY KEY (from_id, to_id)
    #             )
    #         """)
    #         # Session keys table
    #         cursor.execute("""
    #             CREATE TABLE IF NOT EXISTS session_keys (
    #                 session_id TEXT PRIMARY KEY,
    #                 client_id TEXT NOT NULL,
    #                 session_key BLOB NOT NULL,
    #                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    #                 expires_at TIMESTAMP NOT NULL
    #             )
    #         """)
    #         # Notifications table
    #         cursor.execute("""
    #             CREATE TABLE IF NOT EXISTS notifications (
    #                 id INTEGER PRIMARY KEY AUTOINCREMENT,
    #                 client_id TEXT,
    #                 message TEXT,
    #                 notification_type TEXT,
    #                 is_read BOOLEAN DEFAULT 0,
    #                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    #                 action_url TEXT,
    #                 FOREIGN KEY (client_id) REFERENCES clients (client_id)
    #             )
    #         """)
    #         # Client logs table
    #         cursor.execute("""
    #             CREATE TABLE IF NOT EXISTS client_logs (
    #                 id INTEGER PRIMARY KEY AUTOINCREMENT,
    #                 client_id TEXT,
    #                 log_type TEXT,
    #                 message TEXT,
    #                 timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    #                 metadata TEXT,
    #                 FOREIGN KEY (client_id) REFERENCES clients (client_id)
    #             )
    #         """)
    #         conn.commit()


    def register_client(self, client_id, client_name, secret_id, authorized_peers, expires_at):
        """Register a new client in the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO clients (client_id, client_name, secret_id, authorized_peers, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (client_id, client_name, secret_id, json.dumps(authorized_peers), expires_at))
            conn.commit()


    def log_client_activity(self, client_id, log_type, message, metadata=None):
        """Log client activity to the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO client_logs (client_id, log_type, message, metadata)
                VALUES (?, ?, ?, ?)
            """, (client_id, log_type, message, json.dumps(metadata or {})))
            conn.commit()

    def send_notification(self, client_id, message, notification_type='SYSTEM'):
        """Send a notification to a client's dashboard."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notifications (client_id, message, notification_type)
                VALUES (?, ?, ?)
            """, (client_id, message, notification_type))
            conn.commit()

    # Additional methods for handling PSK exchanges, etc.


    def _derive_symmetric_key(self, shared_secret):
        """Derive symmetric key using HKDF"""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kdc-session-key',
            backend=default_backend()
        ).derive(shared_secret)

    def _encrypt_with_key(self, key, data):
        """Encrypt data with AES-CFB"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def _decrypt_with_key(self, key, data):
        """Decrypt data with AES-CFB"""
        iv, encrypted = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()

    def handle_client(self, client_sock, addr):
        """Handle client connection and key exchange"""
        print(f"[KDC] New connection from {addr}")
        try:
            # Phase 1: Key Exchange
            client_sock.sendall(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Receive and decrypt client parameter
            encrypted_param = client_sock.recv(256)
            if len(encrypted_param) != 256:
                raise ValueError("Invalid ciphertext length")

            client_param = self.private_key.decrypt(
                encrypted_param,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Derive session key
            session_key = self._derive_symmetric_key(client_param)
            
            # Send encrypted server parameter
            kdc_param = os.urandom(32)
            encrypted_kdc_param = self._encrypt_with_key(session_key, kdc_param)
            client_sock.sendall(encrypted_kdc_param)

            # Phase 2: Client Requests
            while self._running:
                encrypted_request = client_sock.recv(4096)
                if not encrypted_request:
                    break

                request = self._decrypt_with_key(session_key, encrypted_request)
                response = self._handle_request(request.decode(), session_key)
                
                if response:
                    encrypted_response = self._encrypt_with_key(session_key, response)
                    client_sock.sendall(encrypted_response)

        except Exception as e:
            print(f"[KDC] Error with {addr}: {e}")
        finally:
            client_sock.close()
            print(f"[KDC] Connection closed with {addr}")

    def _handle_request(self, request, session_key):
        """Process client requests"""
        try:
            if request.startswith("REGISTER:"):
                return self._handle_registration(request[9:], session_key)
            elif request.startswith("AUTHENTICATE:"):
                return self._handle_authentication(request[13:], session_key)
            elif request.startswith("GET_PEER_KEY:"):
                return self._handle_peer_key_request(request[13:])
            elif request.startswith("GET_PSK:"):
                return self._handle_psk_request(request[8:])
            else:
                return b"INVALID_REQUEST"
        except Exception as e:
            print(f"[KDC] Request handling error: {e}")
            return b"ERROR"

    def _handle_registration(self, client_data, session_key):
        """Handle new client registration"""
        try:
            data = json.loads(client_data)
            client_id = data['client_id']
            client_name = data['client_name']
            
            # Generate and encrypt client secret
            secret = os.urandom(32)
            encrypted_secret = self._encrypt_with_key(session_key, secret)
            expires_at = datetime.now() + timedelta(days=30)
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO clients 
                    (client_id, client_name, secret_id, authorized_peers, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    client_id,
                    client_name,
                    encrypted_secret,
                    json.dumps([]),
                    expires_at.isoformat()
                ))
                conn.commit()
            
            return b"REGISTRATION_SUCCESS"
        except Exception as e:
            print(f"[KDC] Registration error: {e}")
            return b"REGISTRATION_FAILED"

    def start(self):
        """Start the KDC server"""
        self._running = True
        print(f"[KDC] Starting server on {self.host}:{self.port}")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            
            while self._running:
                try:
                    client_sock, addr = s.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, addr),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self._running:
                        print(f"[KDC] Accept error: {e}")

    def stop(self):
        """Stop the KDC server"""
        self._running = False
        print("[KDC] Server stopping...")



    # #for the dashboard 
    # def _send_notification(self, client_id, message, notification_type='SYSTEM'):
    #     """Send a notification to a client's dashboard"""
    #     try:
    #         with sqlite3.connect(self.db_path) as conn:
    #             cursor = conn.cursor()
    #             cursor.execute("""
    #                 INSERT INTO notifications (client_id, message, notification_type, is_read, created_at)
    #                 VALUES (?, ?, ?, 0, datetime('now'))
    #             """, (client_id, message, notification_type))
    #             conn.commit()
    #     except Exception as e:
    #         print(f"[KDC] Failed to send notification: {e}")

    # def _log_client_activity(self, client_id, log_type, message, metadata=None):
    #     """Log client activity to the database"""
    #     try:
    #         with sqlite3.connect(self.db_path) as conn:
    #             cursor = conn.cursor()
    #             cursor.execute("""
    #                 INSERT INTO client_logs (client_id, log_type, message, metadata, timestamp)
    #                 VALUES (?, ?, ?, ?, datetime('now'))
    #             """, (client_id, log_type, message, json.dumps(metadata or {})))
    #             conn.commit()
    #     except Exception as e:
    #         print(f"[KDC] Failed to log activity: {e}")

if __name__ == '__main__':
    server = KDCServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()