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
from identity_manager import IdentityManager

patch_context()

# Global database lock for thread-safe operations
db_lock = threading.Lock()

class SecureChannelSDK:
    def __init__(self, client_name="SecureClient", client_id=None, identity_dir="."):
        print("[DEBUG] Initializing SecureChannelSDK instance")

        self.identity_dir = Path(identity_dir)
        self.identity_dir.mkdir(parents=True, exist_ok=True)

        self.client_name = client_name
        self.kdc_host = "127.0.0.1"
        self.kdc_port = 5000
        self._background_thread = None
        self.session_keys = {}
        self._background_check_interval = 60
        self.psk = None
        self.kdc_pub_key = None
        self.ecdh_private_key = None

        # Determine client_id by loading existing identity or generating new
        self.client_id = client_id or self._load_existing_identity_id()

        # Compute the path to the identity file
        self.identity_path = self.identity_dir / f".{self.client_id}_identity.json"

        # Remove expired identity if present
        if self.identity_path.exists():
            with open(self.identity_path) as f:
                identity = json.load(f)
            expires_at = datetime.fromisoformat(identity.get("expires_at", "1970-01-01T00:00:00"))
            if datetime.now() > expires_at:
                print(f"[WARNING] Identity expired - deleting identity file")
                self.identity_path.unlink()

        print(f"[DEBUG] Client initialized with ID: {self.client_id[:6]}...")

        # Initialize identity manager
        self.identity_manager = IdentityManager(
            client_id=self.client_id,
            client_name=self.client_name,
            identity_dir=str(self.identity_dir)
        )
        # Initialize database tables
        self._init_database_tables()

    def _load_existing_identity_id(self):
        """Return the client_id from a valid existing identity file, if found."""
        for file in self.identity_dir.glob(".client_*_identity.json"):
            try:
                with open(file) as f:
                    data = json.load(f)
                expires_at = datetime.fromisoformat(data.get("expires_at", "1970-01-01T00:00:00"))
                if datetime.now() < expires_at:
                    client_id = data["client_id"]
                    print(f"[DEBUG] Found valid identity file")
                    return client_id
            except Exception as e:
                print(f"[WARNING] Failed to parse identity file: {str(e)[:50]}")
        # If no valid identity was found, generate new ID
        new_id = f"client_{os.urandom(4).hex()}"
        print(f"[DEBUG] Generating new client ID")
        return new_id

    def _init_database_tables(self):
        """Initialize all required database tables"""
        print(f"[DEBUG] Initializing database tables")
        try:
            with sqlite3.connect(self.identity_manager.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS peer_status (
                        client_id TEXT PRIMARY KEY,
                        is_ready BOOLEAN,
                        last_update TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS psk_exchange (
                        from_id TEXT,
                        to_id TEXT,
                        shared_psk BLOB,
                        PRIMARY KEY (from_id, to_id)
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ecdh_sessions (
                        session_id TEXT PRIMARY KEY,
                        peer_id TEXT NOT NULL,
                        public_key BLOB,
                        created_at TIMESTAMP
                    )
                """)
                conn.commit()
            print(f"[DEBUG] Database tables initialized successfully")
        except sqlite3.Error as e:
            print(f"[ERROR] Failed to initialize database tables: {str(e)[:50]}")
            raise

    def connect_to_kdc(self):
        """Establish secure connection with KDC and register/authenticate"""
        print(f"[DEBUG] Connecting to KDC")

        try:
            with socket.socket() as s:
                s.settimeout(10)
                print(f"[DEBUG] Attempting to connect to KDC")
                s.connect((self.kdc_host, self.kdc_port))

                # Receive KDC's public key
                print(f"[DEBUG] Receiving KDC public key")
                pub_key_data = s.recv(4096)
                if not pub_key_data:
                    raise ValueError("Empty public key received from KDC")

                kdc_pub_key = serialization.load_pem_public_key(pub_key_data)
                self.kdc_pub_key = kdc_pub_key
                print(f"[DEBUG] KDC public key loaded successfully")

                # Generate and send our parameter
                our_param = os.urandom(32)
                print(f"[DEBUG] Generated client parameter")

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
                print(f"[DEBUG] Ciphertext length valid")

                print(f"[DEBUG] Sending encrypted parameter to KDC")
                s.sendall(encrypted_param)

                # Receive KDC's parameter
                print(f"[DEBUG] Waiting for KDC parameter")
                kdc_param_enc = s.recv(4096)
                if not kdc_param_enc:
                    raise ValueError("Empty parameter received from KDC")

                # Derive symmetric key
                print(f"[DEBUG] Deriving symmetric key")
                symmetric_key = self._derive_symmetric_key(our_param)
                kdc_param = self._decrypt_with_key(symmetric_key, kdc_param_enc)
                print(f"[DEBUG] KDC parameter decrypted successfully")

                # Calculate PSK
                self.psk = self._generate_psk(our_param, kdc_param)
                print(f"[DEBUG] PSK established")

                # Handle identity renewal
                if not self.handle_identity_renewal(auto_renew=True):
                    raise Exception("Identity renewal failed")

            # Registration/Authentication
            if not self.identity_manager.is_registered():
                print(f"[DEBUG] Client not registered, initiating registration")
                if not self.identity_manager.register_on_kdc(self.kdc_pub_key):
                    raise Exception("Registration failed")
            else:
                print(f"[DEBUG] Checking authentication status")
                identity = self.identity_manager.load_identity()
                if self.identity_manager.is_expired(identity):
                    print(f"[DEBUG] Identity expired, renewing")
                    if not self.identity_manager.register_on_kdc(self.kdc_pub_key):
                        raise Exception("Renewal failed")

            # Start background thread after successful setup
            self._start_background_checker()

            print(f"[INFO] Secure connection established with KDC")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to connect to KDC: {str(e)[:50]}")
            raise

    def _start_background_checker(self):
        """Start background thread to check expiration periodically"""
        if self._background_thread is not None and self._background_thread.is_alive():
            print(f"[DEBUG] Background checker already running")
            return

        def checker():
            print(f"[DEBUG] Background checker started")
            while True:
                try:
                    self._init_database_tables()
                    self.handle_identity_renewal(auto_renew=False)
                except Exception as e:
                    print(f"[ERROR] Background check failed: {str(e)[:50]}")
                time.sleep(self._background_check_interval)

        self._background_thread = threading.Thread(
            target=checker,
            daemon=True
        )
        self._background_thread.start()
        print(f"[DEBUG] Background checker thread started")

    def handle_identity_renewal(self, auto_renew=True):
        """Check and securely handle identity expiration or renewal"""
        print(f"[DEBUG] Checking identity status")
        status = self.identity_manager.check_identity_expiration()

        if status == "not_registered":
            print(f"[INFO] Not registered - proceeding with registration")
            success = self.identity_manager.register_on_kdc(self.kdc_pub_key)
            if success:
                try:
                    self._start_background_checker()
                except Exception as e:
                    print(f"[ERROR] Failed to start background checker: {str(e)[:50]}")
            return success

        elif status == "expired":
            print(f"[WARNING] Identity expired - generating new identity")
            success = self.identity_manager.register_on_kdc(self.kdc_pub_key)
            if success:
                try:
                    self._start_background_checker()
                except Exception as e:
                    print(f"[ERROR] Failed to start background checker: {str(e)[:50]}")
            return success

        elif status.startswith("expiring_soon"):
            if auto_renew:
                print(f"[INFO] Identity expiring soon - auto-renewing")
                success = self.identity_manager.register_on_kdc(self.kdc_pub_key)
                if success:
                    try:
                        self._start_background_checker()
                    except Exception as e:
                        print(f"[ERROR] Failed to start background checker: {str(e)[:50]}")
                return success
            else:
                print(f"\n[WARNING] Your identity will expire soon ({status.split('(')[1]})")
                choice = input("Would you like to renew now? (y/n): ").lower()
                if choice == 'y':
                    return self.identity_manager.register_on_kdc(self.kdc_pub_key)
                return False

        print(f"[DEBUG] Identity is valid")
        return True

    def wait_for_peer_ready(self, peer_id, port=6000, timeout=60):
        """Wait for peer to open socket (polling)"""
        print(f"[DEBUG] Waiting for peer {peer_id[:6]}... to be ready (timeout={timeout}s)")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=2):
                    print(f"[DEBUG] Peer is ready")
                    return
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(1)
        raise TimeoutError(f"Peer not ready on port {port} after {timeout} seconds")

    def connect_to_peer(self, peer_id, host='127.0.0.1', port=6000, max_attempts=3):
        """Connect to peer using ECDH with PSK fallback"""
        print(f"[DEBUG] Attempting to connect to peer {peer_id[:6]}...")
        
        for attempt in range(max_attempts):
            try:
                print(f"[DEBUG] Attempt {attempt + 1}/{max_attempts}")
                self.wait_for_peer_ready(peer_id, port=port, timeout=60)
                print(f"[DEBUG] Peer is ready, initiating connection")
                    
                try:
                    print(f"[DEBUG] Attempting ECDH connection")
                    sock = socket.socket()
                    sock.settimeout(10)
                    sock.connect((host, port))
                    
                    # ECDH key generation
                    print(f"[DEBUG] Generating ECDH key pair")
                    self.ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
                    our_pubkey = self.ecdh_private_key.public_key()

                    # Send public key
                    print(f"[DEBUG] Sending our public key")
                    sock.sendall(our_pubkey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))

                    # Receive peer's public key
                    print(f"[DEBUG] Waiting for peer's public key")
                    peer_pubkey_data = sock.recv(4096)
                    if not peer_pubkey_data:
                        raise ValueError("Empty public key received from peer")
                    
                    peer_pubkey = serialization.load_pem_public_key(
                        peer_pubkey_data,
                        backend=default_backend()
                    )
                    print(f"[DEBUG] Peer public key loaded successfully")

                    # Perform key exchange
                    print(f"[DEBUG] Performing ECDH key exchange")
                    shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_pubkey)

                    print(f"[DEBUG] Deriving session key")
                    session_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'ecdh-session-key',
                        backend=default_backend()
                    ).derive(shared_secret)

                    # Identity exchange
                    print(f"[DEBUG] Initiating identity verification")
                    identify_prompt = sock.recv(1024)
                    if identify_prompt != b"IDENTIFY":
                        raise ValueError("Peer did not request identity as expected")

                    print(f"[DEBUG] Sending our identity")
                    sock.sendall(self.client_id.encode())

                    print(f"[DEBUG] Connection established successfully")
                    return EncryptedSocket(sock, session_key)

                except Exception as e:
                    print(f"[WARNING] ECDH failed, falling back to PSK: {str(e)[:50]}")
                    return self._connect_with_psk(peer_id, host, port)
                    
            except Exception as e:
                if attempt == max_attempts - 1:
                    print(f"[ERROR] Final connection attempt failed: {str(e)[:50]}")
                    raise
                print(f"[WARNING] Attempt {attempt + 1} failed: {str(e)[:50]}")
                time.sleep(1)

    def _connect_with_psk(self, peer_id, host, port):
        """Fallback connection using pre-shared key"""
        print(f"[DEBUG] Attempting PSK connection")
        
        try:
            print(f"[DEBUG] Retrieving PSK for peer")
            peer_psk = self.receive_shared_psk(peer_id)
            if not peer_psk:
                raise ValueError("No PSK available for this peer")
            
            print(f"[DEBUG] Configuring PSK context")
            ctx = Context(TLSv1_2_METHOD)
            ctx.set_cipher_list(b'PSK')
            ctx.set_psk_client_callback(lambda c, h: (self.client_id.encode(), peer_psk))

            print(f"[DEBUG] Establishing socket connection")
            sock = socket.socket()
            sock.settimeout(10)
            sock.connect((host, port))
            
            print(f"[DEBUG] Performing TLS-PSK handshake")
            conn = Connection(ctx, sock)
            conn.set_connect_state()
            conn.do_handshake()
            
            print(f"[DEBUG] PSK connection established")
            return conn
            
        except Exception as e:
            print(f"[ERROR] PSK connection failed: {str(e)[:50]}")
            raise

    def listen_for_peers(self, port=6000):
        """Start listener in a daemon thread (non-blocking)."""
        print(f"[DEBUG] Starting peer listener on port {port}")
        
        def listener_thread():
            with socket.socket() as s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('0.0.0.0', port))
                    s.listen()
                    self._update_peer_status(True)
                    print(f"[INFO] Listener ready on port {port}")
                    
                    while True:
                        try:
                            conn, addr = s.accept()
                            print(f"[DEBUG] New connection from {addr[0]}")
                            threading.Thread(
                                target=self._handle_incoming_connection,
                                args=(conn,),
                                daemon=True
                            ).start()
                        except Exception as e:
                            print(f"[ERROR] Listener accept error: {str(e)[:50]}")
                            break
                except Exception as e:
                    print(f"[ERROR] Listener setup failed: {str(e)[:50]}")
                    raise

        threading.Thread(target=listener_thread, daemon=True).start()
        print(f"[DEBUG] Listener thread started")

    def _handle_incoming_connection(self, conn):
        """Handle both ECDH and PSK connections"""
        try:
            first_msg = conn.recv(4096, socket.MSG_PEEK)
            if not first_msg:
                print("[DEBUG] Empty initial message - closing connection")
                conn.close()
                return
                
            if b"-----BEGIN PUBLIC KEY-----" in first_msg:
                print(f"[DEBUG] Detected ECDH connection")
                self._handle_ecdh_connection(conn)
            else:
                print(f"[DEBUG] Detected PSK connection")
                self._handle_psk_connection(conn)
                
        except Exception as e:
            print(f"[ERROR] Connection handling failed: {str(e)[:50]}")
            try:
                conn.close()
            except:
                pass

    def _handle_ecdh_connection(self, conn):
        """Process ECDH key exchange"""
        try:
            print(f"[DEBUG] Handling ECDH connection")
            
            peer_pubkey_data = conn.recv(4096)
            if not peer_pubkey_data:
                raise ValueError("Empty public key received")
                
            print(f"[DEBUG] Loading peer's public key")
            peer_pubkey = serialization.load_pem_public_key(peer_pubkey_data)
            
            print(f"[DEBUG] Generating ECDH key pair")
            ecdh_private = ec.generate_private_key(ec.SECP384R1())
            our_pubkey = ecdh_private.public_key()
            
            print(f"[DEBUG] Sending our public key")
            conn.sendall(our_pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            print(f"[DEBUG] Performing key exchange")
            shared_secret = ecdh_private.exchange(ec.ECDH(), peer_pubkey)
            
            print(f"[DEBUG] Deriving session key")
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecdh-session-key',
                backend=default_backend()
            ).derive(shared_secret)
            
            print(f"[DEBUG] Authenticating peer")
            peer_id = self._authenticate_ecdh_peer(conn, session_key)
            if not peer_id:
                raise ValueError("Peer authentication failed")
                
            print(f"[DEBUG] Peer authenticated")
            self.session_keys[peer_id] = session_key
            self._handle_secure_connection(conn, session_key)
            
        except Exception as e:
            print(f"[ERROR] ECDH handling failed: {str(e)[:50]}")
            try:
                conn.close()
            except:
                pass
            raise

    def _authenticate_ecdh_peer(self, conn, session_key):
        """Securely authenticate ECDH peer by requesting and validating identity."""
        try:
            print(f"[DEBUG] Requesting peer identity")
            conn.sendall(b"IDENTIFY")

            peer_id = conn.recv(1024).decode().strip()
            if not peer_id:
                raise ValueError("Empty peer ID received")
                
            print(f"[DEBUG] Received peer ID")

            if not self.identity_manager.is_peer_authorized(peer_id):
                print(f"[WARNING] Unauthorized peer")
                return None

            print(f"[DEBUG] Peer authorized")
            return peer_id
            
        except Exception as e:
            print(f"[ERROR] Authentication failed: {str(e)[:50]}")
            return None

    def _handle_psk_connection(self, conn):
        """Process PSK connection"""
        try:
            print(f"[DEBUG] Handling PSK connection")
            
            ctx = Context(TLSv1_2_METHOD)
            ctx.set_cipher_list(b'PSK')
            ctx.set_psk_server_callback(self._verify_peer)
            
            print(f"[DEBUG] Setting up TLS connection")
            ssl_conn = Connection(ctx, conn)
            ssl_conn.set_accept_state()
            try:
                ssl_conn.do_handshake()
            except Exception as e:
                print(f"[ERROR] PSK handshake failed: {str(e)[:50]}")
                raise
            
            print(f"[DEBUG] PSK handshake complete")
            self._handle_peer_connection(ssl_conn)
            
        except Exception as e:
            print(f"[ERROR] PSK handling failed: {str(e)[:50]}")
            try:
                conn.close()
            except:
                pass
            raise

    def _handle_secure_connection(self, conn, session_key):
        """Handle secure communication with peer"""
        print(f"[DEBUG] Starting secure communication")
        encrypted_conn = EncryptedSocket(conn, session_key)
        try:
            while True:
                data = encrypted_conn.recv(1024)
                if not data:
                    print(f"[DEBUG] Connection closed by peer")
                    break
                print(f"[MESSAGE RECEIVED] Content: {data.decode()}")
                response = f"ACK from {self.client_id[:6]}..."
                encrypted_conn.send(response.encode())
                print(f"[MESSAGE SENT] Content: {response}")
        except Exception as e:
            print(f"[ERROR] Secure communication error: {str(e)[:50]}")
        finally:
            encrypted_conn.close()
            print(f"[DEBUG] Secure connection closed")

    def _handle_peer_connection(self, ssl_conn):
        """Handle established PSK connection"""
        print(f"[DEBUG] Handling peer connection")
        try:
            while True:
                data = ssl_conn.recv(1024)
                if not data:
                    print(f"[DEBUG] Peer closed connection")
                    break
                print(f"[MESSAGE RECEIVED] Content: {data.decode()}")
                response = f"ACK from {self.client_id[:6]}..."
                ssl_conn.send(response.encode())
                print(f"[MESSAGE SENT] Content: {response}")
        except Exception as e:
            print(f"[ERROR] Peer communication error: {str(e)[:50]}")
        finally:
            ssl_conn.close()
            print(f"[DEBUG] Peer connection closed")

    def _update_peer_status(self, ready=True):
        """Update our ready status in the database"""
        print(f"[DEBUG] Updating peer status (ready={ready})")
        try:
            with sqlite3.connect(self.identity_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO peer_status 
                    (client_id, is_ready, last_update)
                    VALUES (?, ?, ?)
                """, (self.client_id, ready, datetime.now().isoformat()))
                conn.commit()
            print(f"[DEBUG] Peer status updated successfully")
        except sqlite3.Error as e:
            print(f"[ERROR] Failed to update peer status: {str(e)[:50]}")

    def _verify_peer(self, conn, identity):
        """Verify peer identity and return PSK for PSK connections"""
        try:
            peer_id = identity.decode()
            print(f"[DEBUG] Verifying peer {peer_id[:6]}...")
            
            if not self.identity_manager.is_peer_authorized(peer_id):
                print(f"[WARNING] Peer not authorized")
                return None
            
            print(f"[DEBUG] Retrieving PSK for peer")
            try:
                psk = self.receive_shared_psk(peer_id)
                if not psk:
                    raise ValueError("No PSK available for this peer")
                    
                print(f"[DEBUG] Peer verified successfully")
                return psk
            except Exception as e:
                print(f"[ERROR] Failed to retrieve PSK: {str(e)[:50]}")
                return None
                
        except Exception as e:
            print(f"[ERROR] Peer verification failed: {str(e)[:50]}")
            return None

    def _derive_symmetric_key(self, shared_secret):
        """Derive symmetric key using HKDF"""
        print(f"[DEBUG] Deriving symmetric key")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-channel-key',
            backend=default_backend()
        )
        key = hkdf.derive(shared_secret)
        return key

    def _encrypt_with_key(self, key, data):
        """Encrypt data with symmetric key"""
        print(f"[DEBUG] Encrypting data (length={len(data)})")
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = iv + encryptor.update(data) + encryptor.finalize()
        print(f"[DEBUG] Encryption complete")
        return encrypted

    def _decrypt_with_key(self, key, data):
        """Decrypt data with symmetric key"""
        print(f"[DEBUG] Decrypting data (length={len(data)})")
        iv, encrypted = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        print(f"[DEBUG] Decryption complete")
        return decrypted

    def _generate_psk(self, client_param, kdc_param):
        """Generate PSK from parameters"""
        print(f"[DEBUG] Generating PSK")
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(client_param + kdc_param)
        psk = h.finalize()
        return psk
    
    def generate_and_distribute_shared_psk(self, peer_id):
        """Generate and store PSK for peer connections"""
        print(f"\n[DEBUG] Generating PSK for peer {peer_id[:6]}...")
        
        try:
            with db_lock:
                self._init_database_tables()
                
                # Clean up any existing PSKs for this pair
                with sqlite3.connect(self.identity_manager.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        DELETE FROM psk_exchange
                        WHERE (from_id = ? AND to_id = ?)
                        OR (from_id = ? AND to_id = ?)
                    """, (self.client_id, peer_id, peer_id, self.client_id))
                    conn.commit()
                
                # Generate and store new PSK
                shared_psk = os.urandom(32)
                
                with sqlite3.connect(self.identity_manager.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Store in both directions
                    cursor.execute("""
                        INSERT INTO psk_exchange 
                        (from_id, to_id, shared_psk)
                        VALUES (?, ?, ?)
                    """, (self.client_id, peer_id, shared_psk))
                    
                    cursor.execute("""
                        INSERT INTO psk_exchange 
                        (from_id, to_id, shared_psk)
                        VALUES (?, ?, ?)
                    """, (peer_id, self.client_id, shared_psk))
                    
                    conn.commit()
                
            print(f"[DEBUG] PSK stored successfully for peer {peer_id[:6]}...")
            return shared_psk
            
        except Exception as e:
            print(f"[ERROR] Failed to generate/distribute PSK: {str(e)[:50]}")
            raise

    def receive_shared_psk(self, peer_id):
        """Retrieve PSK for a peer connection"""
        print(f"\n[DEBUG] Retrieving PSK for peer {peer_id[:6]}...")

        for attempt in range(20):  # Wait up to 10 seconds
            try:
                with db_lock:
                    with sqlite3.connect(self.identity_manager.db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        
                        # Check both directions
                        cursor.execute("""
                            SELECT shared_psk FROM psk_exchange
                            WHERE (from_id = ? AND to_id = ?)
                            OR (from_id = ? AND to_id = ?)
                        """, (peer_id, self.client_id, self.client_id, peer_id))
                        
                        result = cursor.fetchone()
                        if result:
                            print(f"[DEBUG] Retrieved PSK")
                            return result['shared_psk']
                        
                print(f"[DEBUG] PSK not found yet (attempt {attempt + 1})")
                time.sleep(0.5)
                
            except sqlite3.Error as e:
                print(f"[ERROR] Database error: {str(e)[:50]}")
                time.sleep(0.5)
            except Exception as e:
                print(f"[ERROR] PSK retrieval failed: {str(e)[:50]}")
                time.sleep(0.5)

        print(f"[ERROR] Timed out waiting for PSK from {peer_id[:6]}...")
        raise TimeoutError(f"Timed out waiting for PSK from {peer_id[:6]}...")


class EncryptedSocket:
    """Wrapper for socket with ECDH-derived encryption"""
    def __init__(self, socket, session_key):
        print(f"[DEBUG] Creating EncryptedSocket")
        self.socket = socket
        self.session_key = session_key
        
    def send(self, data):
        """Encrypt and send data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            print(f"[DEBUG] Encrypting {len(data)} bytes")
            
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = iv + encryptor.update(data) + encryptor.finalize()
            
            print(f"[DEBUG] Sending encrypted data")
            self.socket.sendall(encrypted)
            
        except Exception as e:
            print(f"[ERROR] Failed to send encrypted data: {str(e)[:50]}")
            raise
        
    def recv(self, bufsize):
        """Receive and decrypt data"""
        try:
            data = self.socket.recv(bufsize)
            if not data:
                print(f"[DEBUG] Received empty data (connection closed)")
                return None
                
            print(f"[DEBUG] Received encrypted data")
            iv, encrypted = data[:16], data[16:]
            
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            
            print(f"[DEBUG] Decrypted data")
            return decrypted
            
        except Exception as e:
            print(f"[ERROR] Failed to receive/decrypt data: {str(e)[:50]}")
            raise
        
    def close(self):
        """Close the socket connection"""
        print(f"[DEBUG] Closing encrypted socket")
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.socket.close()
        print(f"[DEBUG] Socket closed")