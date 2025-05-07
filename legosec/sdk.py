import os
import json
import sqlite3
import socket
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from OpenSSL.SSL import Context, Connection, TLSv1_2_METHOD
from openssl_psk import patch_context
from identity_manager import IdentityManager

patch_context()

class SecureChannelSDK:
    def __init__(self, client_name=None, client_id=None, kdc_host='127.0.0.1', kdc_port=5000):
        # Client identification
        self.client_id = client_id or f"client_{os.urandom(4).hex()}"
        self.client_name = client_name or f"Client-{self.client_id[-4:]}"
        
        # KDC connection parameters
        self.kdc_host = kdc_host
        self.kdc_port = kdc_port
        
        # Security parameters
        self.psk = None  # For KDC communication
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.session_keys = {}  # For peer connections
        self.ecdh_private_keys = {}  # Stores temporary ECDH keys
        
        # Identity management
        self.identity_manager = IdentityManager(
            client_id=self.client_id,
            client_name=self.client_name
        )
        
        # Background services
        self._background_check_interval = 3600
        self._background_thread = None
        self._init_database_tables()
        self._start_background_checker()

    def _init_database_tables(self):
        """Initialize all required database tables"""
        with sqlite3.connect(self.identity_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Peer status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer_status (
                    client_id TEXT PRIMARY KEY,
                    is_ready BOOLEAN,
                    last_update TIMESTAMP
                )
            """)
            
            # PSK exchange table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS psk_exchange (
                    from_id TEXT,
                    to_id TEXT,
                    shared_psk BLOB,
                    PRIMARY KEY (from_id, to_id)
                )
            """)
            
            # ECDH session info table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ecdh_sessions (
                    session_id TEXT PRIMARY KEY,
                    peer_id TEXT NOT NULL,
                    public_key BLOB,
                    created_at TIMESTAMP
                )
            """)
            conn.commit()

    def connect_to_kdc(self):
        """Establish secure connection with KDC and register/authenticate"""
        print(f"[{self.client_id}] Connecting to KDC...")
        
        with socket.socket() as s:
            s.connect((self.kdc_host, self.kdc_port))
            
            # Receive KDC's public key
            pub_key_data = s.recv(4096)
            kdc_pub_key = serialization.load_pem_public_key(pub_key_data)
            print(f"[{self.client_id}] Received KDC public key.")

            # Generate and send our parameter
            our_param = os.urandom(32)
            encrypted_param = kdc_pub_key.encrypt(
                our_param,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if len(encrypted_param) != 256:
                raise ValueError(f"Invalid ciphertext length: {len(encrypted_param)} bytes")
            print(f"[DEBUG] Ciphertext length valid: {len(encrypted_param)} bytes")
            
            s.sendall(encrypted_param)
            
            # Receive KDC's parameter
            kdc_param_enc = s.recv(4096)
            
            # Derive symmetric key
            symmetric_key = self._derive_symmetric_key(our_param)
            kdc_param = self._decrypt_with_key(symmetric_key, kdc_param_enc)
            
            # Calculate PSK
            self.psk = self._generate_psk(our_param, kdc_param)

        # Registration/Authentication
        if not self.identity_manager.is_registered():
            print(f"[{self.client_id}] Registering with KDC...")
            self.identity_manager.register_on_kdc(kdc_pub_key)
        else:
            print(f"[{self.client_id}] Authenticating with KDC...")
            if not self.identity_manager.renew_identity(kdc_public_key=kdc_pub_key, auto_renew=True):
                print(f"[{self.client_id}] Identity renewal failed")
        
        print(f"[{self.client_id}] Secure connection established with KDC")


        

    def wait_for_peer_ready(self, peer_id, timeout=30, check_interval=0.5):
        """Wait until peer is ACTUALLY listening on its port"""
        start_time = time.time()
        peer_port = 6002  # Or fetch from config/DB
        
        while time.time() - start_time < timeout:
            # Check if peer is registered (exists in DB)
            with sqlite3.connect(self.identity_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM clients WHERE client_id = ?", (peer_id,))
                if not cursor.fetchone():
                    time.sleep(check_interval)
                    continue  # Peer not registered yet
            
            # Check if peer's port is open (socket-level check)
            try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect(('127.0.0.1', peer_port))  # Replace with peer's actual IP
                sock.close()
                return True  # Port is open!
            except (socket.timeout, ConnectionRefusedError):
                time.sleep(check_interval)
        
        raise TimeoutError(f"Peer {peer_id} not listening after {timeout} seconds")
    # In SecureChannelSDK class

    def connect_to_peer(self, peer_id, host='127.0.0.1', port=6000, max_attempts=3):
        for attempt in range(max_attempts):
            try:
                self.wait_for_peer_ready(peer_id, timeout=60)
                print(f"[{self.client_id}] Waiting for peer {peer_id} to be ready...")
                    
                # Try ECDH first
                try:
                    print(f"[{self.client_id}] Attempting ECDH connection...")
                    sock = socket.socket()
                    sock.connect((host, port))
                    
                    # Generate fresh ECDH keys
                    self.ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
                    our_pubkey = self.ecdh_private_key.public_key()
                    
                    # Send our public key
                    sock.sendall(our_pubkey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                    
                    # Receive peer's public key
                    peer_pubkey_data = sock.recv(4096)
                    peer_pubkey = serialization.load_pem_public_key(
                        peer_pubkey_data,
                        backend=default_backend()
                    )
                    
                    # Perform ECDH key exchange
                    shared_secret = self.ecdh_private_key.exchange(
                        ec.ECDH(),
                        peer_pubkey
                    )
                    
                    # Derive session key
                    session_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'ecdh-session-key',
                        backend=default_backend()
                    ).derive(shared_secret)
                    
                    # Return the encrypted socket
                    return EncryptedSocket(sock, session_key)
                    
                except Exception as e:
                    print(f"[{self.client_id}] ECDH failed, falling back to PSK: {e}")
                    return self._connect_with_psk(peer_id, host, port)
                    
            except Exception as e:
                if attempt == max_attempts - 1:
                    raise
                print(f"[{self.client_id}] Attempt {attempt + 1} failed: {e}")
                time.sleep(1)

    def _connect_with_psk(self, peer_id, host, port):
        """Fallback connection using pre-shared key"""
        peer_psk = self.receive_shared_psk(peer_id)
        
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
        """Start listener in a daemon thread (non-blocking)."""
        def listener_thread():
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen()
                self._update_peer_status(True)  # Mark as ready
                print(f"[{self.client_id}] Listener ready on port {port}")
                
                while True:
                    try:
                        conn, addr = s.accept()
                        threading.Thread(
                            target=self._handle_incoming_connection,
                            args=(conn,),
                            daemon=True
                        ).start()
                    except Exception as e:
                        print(f"[{self.client_id}] Listener error: {e}")
                        break

        # Start the listener in a daemon thread (won't block main program)
        threading.Thread(target=listener_thread, daemon=True).start()
    def _handle_incoming_connection(self, conn):
        """Handle both ECDH and PSK connections"""
        try:
            # Peek at first message to determine connection type
            first_msg = conn.recv(4096, socket.MSG_PEEK)
            
            if b"-----BEGIN PUBLIC KEY-----" in first_msg:
                # ECDH connection
                self._handle_ecdh_connection(conn)
            else:
                # PSK connection
                self._handle_psk_connection(conn)
                
        except Exception as e:
            print(f"[{self.client_id}] Connection error: {e}")
            conn.close()

    def _handle_ecdh_connection(self, conn):
        """Process ECDH key exchange"""
        # Receive peer's public key
        peer_pubkey = serialization.load_pem_public_key(conn.recv(4096))
        
        # Generate our key pair
        ecdh_private = ec.generate_private_key(ec.SECP384R1())
        our_pubkey = ecdh_private.public_key()
        
        # Send our public key
        conn.sendall(our_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        # Perform key exchange
        shared_secret = ecdh_private.exchange(ec.ECDH(), peer_pubkey)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh-session-key',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Get peer_id from the connection (would need proper authentication here)
        peer_id = self._authenticate_ecdh_peer(conn, session_key)
        if peer_id:
            self.session_keys[peer_id] = session_key
            self._handle_secure_connection(conn, session_key)

    def _authenticate_ecdh_peer(self, conn, session_key):
        """Authenticate peer in ECDH connection"""
        # In a real implementation, this would verify the peer's identity
        # through the KDC using the session key
        return "peer_id_placeholder"  # Replace with actual authentication

    def _start_background_checker(self):
        """Start background thread to check expiration periodically"""
        if self._background_thread and self._background_thread.is_alive():
            return

        def checker():
            while True:
                self.identity_manager.renew_identity()
                time.sleep(self._background_check_interval)

        self._background_thread = threading.Thread(
            target=checker,
            daemon=True
        )
        self._background_thread.start()

    def _handle_psk_connection(self, conn):
        """Process PSK connection"""
        ctx = Context(TLSv1_2_METHOD)
        ctx.set_cipher_list(b'PSK')
        ctx.set_psk_server_callback(self._verify_peer)
        
        ssl_conn = Connection(ctx, conn)
        ssl_conn.set_accept_state()
        ssl_conn.do_handshake()
        
        # Rest of PSK handling
        self._handle_peer_connection(ssl_conn)

    def _handle_secure_connection(self, conn, session_key):
        """Handle secure communication with peer"""
        encrypted_conn = EncryptedSocket(conn, session_key)
        try:
            while True:
                data = encrypted_conn.recv(1024)
                if not data:
                    break
                print(f"[{self.client_id}] Received: {data.decode()}")
                encrypted_conn.send(f"ACK from {self.client_id}".encode())
        finally:
            encrypted_conn.close()

    def _handle_peer_connection(self, ssl_conn):
        """Handle established PSK connection"""
        try:
            while True:
                data = ssl_conn.recv(1024)
                if not data:
                    break
                print(f"[{self.client_id}] Received from peer: {data.decode()}")
                ssl_conn.send(f"ACK from {self.client_id}".encode())
        except Exception as e:
            print(f"[{self.client_id}] Peer connection error: {e}")
        finally:
            ssl_conn.close()

    def _update_peer_status(self, ready=True):
        """Update our ready status in the database"""
        with sqlite3.connect(self.identity_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO peer_status 
                (client_id, is_ready, last_update)
                VALUES (?, ?, ?)
            """, (self.client_id, ready, datetime.now().isoformat()))
            conn.commit()

    def _verify_peer(self, conn, identity):
        """Verify peer identity and return PSK for PSK connections"""
        peer_id = identity.decode()
        print(f"[{self.client_id}] Verifying peer {peer_id}")
        
        if not self.identity_manager.is_peer_authorized(peer_id):
            print(f"[{self.client_id}] Peer {peer_id} not authorized")
            return None
        
        try:
            psk = self.receive_shared_psk(peer_id)
            print(f"[{self.client_id}] Verified peer {peer_id}")
            return psk
        except Exception as e:
            print(f"[{self.client_id}] PSK verification failed: {e}")
            return None

    # ... (keep all other existing helper methods unchanged)
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


    def generate_and_distribute_shared_psk(self, peer_id):
        """Generate and store PSK for peer connections"""
        print(f"\n[DEBUG][{self.client_name}] Generating PSK for peer {peer_id}")
        
        # Generate a new PSK
        shared_psk = os.urandom(32)
        print(f"[DEBUG][{self.client_name}] Generated PSK: {shared_psk.hex()}")
        
        # Store in both directions (A→B and B→A)
        with sqlite3.connect(self.identity_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Ensure table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS psk_exchange (
                    from_id TEXT,
                    to_id TEXT,
                    shared_psk BLOB,
                    PRIMARY KEY (from_id, to_id)
                )
            """)
            
            # Store PSK in both directions
            cursor.execute("""
                INSERT OR REPLACE INTO psk_exchange (from_id, to_id, shared_psk)
                VALUES (?, ?, ?)
            """, (self.client_id, peer_id, shared_psk))
            
            cursor.execute("""
                INSERT OR REPLACE INTO psk_exchange (from_id, to_id, shared_psk)
                VALUES (?, ?, ?)
            """, (peer_id, self.client_id, shared_psk))
            
            conn.commit()
        
        print(f"[DEBUG][{self.client_name}] PSK stored in DB in both directions")
        return shared_psk

    def receive_shared_psk(self, peer_id):
        """Retrieve PSK for a peer connection"""
        print(f"\n[DEBUG][{self.client_name}] Attempting to receive PSK from {peer_id}")

        for _ in range(20):  # wait up to 10 seconds
            with sqlite3.connect(self.identity_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS psk_exchange (
                        from_id TEXT,
                        to_id TEXT,
                        shared_psk BLOB,
                        PRIMARY KEY (from_id, to_id)
                    )
                """)  

                # Check if the PSK is available in the database
                cursor.execute("""
                    SELECT shared_psk FROM psk_exchange
                    WHERE from_id = ? AND to_id = ?
                """, (peer_id, self.client_id))

                result = cursor.fetchone()
                if result:
                    print(f"[DEBUG][{self.client_name}] Found PSK from {peer_id}: {result[0].hex()}")
                    return result[0]
                
            time.sleep(0.5)

        print(f"[DEBUG][{self.client_name}] No PSK found from {peer_id} after waiting")
        raise TimeoutError(f"Timed out waiting for PSK from {peer_id}")


class EncryptedSocket:
    """Wrapper for socket with ECDH-derived encryption"""
    def __init__(self, socket, session_key):
        self.socket = socket
        self.session_key = session_key
        
    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = iv + encryptor.update(data) + encryptor.finalize()
        self.socket.sendall(encrypted)
        
    def recv(self, bufsize):
        data = self.socket.recv(bufsize)
        if not data:
            return None
        iv, encrypted = data[:16], data[16:]
        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()
        
    def close(self):
        self.socket.close()


