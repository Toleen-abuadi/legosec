import os
import json
import socket
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Register SQLite3 datetime handlers (Python 3.12+ compatibility)
sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda s: datetime.fromisoformat(s.decode()))

class IdentityManager:
    def __init__(self, client_id, client_name, identity_dir=".", db_path="kdc_database.db"):
        """Initialize IdentityManager with secure logging"""
        self.db_path = db_path
        self.client_id = client_id
        self.client_name = client_name
        self.identity_dir = Path(identity_dir)
        self.identity_path = self.identity_dir / f".{self.client_id}_identity.json"

        print(f"[INFO][IdentityManager] Initializing for client {client_id}")
        
        if self.identity_path.exists():
            if not self._is_identity_valid():
                print(f"[WARN][IdentityManager] Invalid identity detected - removing file")
                try:
                    self.identity_path.unlink()
                except Exception as e:
                    print(f"[ERROR][IdentityManager] Failed to remove invalid identity: {str(e)}")

    def _is_identity_valid(self):
        """Securely checks if the identity file is valid"""
        try:
            with open(self.identity_path, "r") as f:
                data = json.load(f)
            
            expires_at = datetime.fromisoformat(data.get("expires_at", "1970-01-01T00:00:00"))
            valid = datetime.now() < expires_at
            
            if valid:
                print(f"[DEBUG][IdentityManager] Valid identity found (expires: {expires_at})")
            else:
                print(f"[DEBUG][IdentityManager] Expired identity (was valid until {expires_at})")
            
            return valid
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Identity validation error: {str(e)}")
            return False
    
    def _init_database(self):
        """Initialize database tables with secure logging"""
        print(f"[DEBUG][IdentityManager] Initializing database schema")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS clients (
                        client_id TEXT PRIMARY KEY,
                        client_name TEXT NOT NULL, 
                        secret_id BLOB NOT NULL,
                        authorized_peers TEXT,
                        expires_at TIMESTAMP NOT NULL,
                        public_key BLOB,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(f"[ERROR][IdentityManager] Database initialization failed: {str(e)}")
            raise

    def is_registered(self):
        """Check registration status without sensitive info"""
        exists = self.identity_path.exists()
        print(f"[DEBUG][IdentityManager] Registration check: {'Found' if exists else 'Not found'}")
        return exists

    def load_identity(self):
        """Securely load identity data"""
        print(f"[DEBUG][IdentityManager] Loading identity file")
        
        if not self.is_registered():
            return None
            
        try:
            with open(self.identity_path, 'r') as f:
                data = json.load(f)
                
            if not all(key in data for key in ['client_id', 'client_name', 'encrypted_secret', 'expires_at']):
                print("[WARN][IdentityManager] Identity file missing required fields")
                return None
                
            return data
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Failed to load identity: {str(e)}")
            return None

    def is_expired(self, identity_data):
        """Check expiration status securely"""
        if not identity_data or 'expires_at' not in identity_data:
            print("[WARN][IdentityManager] Invalid identity data format")
            return True
            
        try:
            expires_at = datetime.fromisoformat(identity_data['expires_at'])
            expired = datetime.now() > expires_at
            print(f"[DEBUG][IdentityManager] Identity {'expired' if expired else 'valid'}")
            return expired
        except Exception as e:
            print(f"[ERROR][IdentityManager] Expiration check failed: {str(e)}")
            return True

    def store_identity(self, encrypted_secret, expires_at):
        """Securely store identity information"""
        print(f"[DEBUG][IdentityManager] Storing new identity")
        
        data = {
            'client_id': self.client_id,
            'client_name': self.client_name,
            'encrypted_secret': encrypted_secret.hex(),  # Stored as hex for serialization
            'expires_at': expires_at.isoformat(),
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            self.identity_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.identity_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            # Verify the file was created
            if not self.identity_path.exists():
                raise IOError("Identity file not created")
                
            print("[INFO][IdentityManager] Identity stored successfully")
            return True
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Failed to store identity: {str(e)}")
            return False

    def register_on_kdc(self, kdc_public_key):
        """Secure client registration with KDC"""
        print(f"[INFO][IdentityManager] Registering client {self.client_id[:6]}...")
        
        
        try:
            # Generate and protect client secret
            secret = os.urandom(32)
            print(f"[DEBUG][IdentityManager] Generated client secret (length: {len(secret)})")
            
            expires_at = datetime.now() + timedelta(days=7)
            
            # Encrypt secret without logging sensitive data
            encrypted_secret = kdc_public_key.encrypt(
                secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[DEBUG][IdentityManager] Secret encrypted (length: {len(encrypted_secret)})")

            # Database operations
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO clients 
                    (client_id, client_name, secret_id, authorized_peers, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    self.client_id,
                    self.client_name,
                    encrypted_secret,
                    json.dumps([]),  # Start with empty peer list
                    expires_at.isoformat()
                ))
                conn.commit()

            if self.store_identity(encrypted_secret, expires_at):
                print(f"[INFO][IdentityManager] Registration successful for {self.client_id[:6]}...")
                return True
                
            return False
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Registration failed: {str(e)}")
            return False

    def authenticate_with_kdc(self, encrypted_secret):
        """Secure authentication with KDC"""
        print(f"[DEBUG][IdentityManager] Authenticating client {self.client_id[:6]}...")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT secret_id, expires_at FROM clients 
                    WHERE client_id = ?
                """, (self.client_id,))
                result = cursor.fetchone()

                if not result:
                    print("[WARN][IdentityManager] Client not found in database")
                    return False

                stored_secret, expires_at = result
                
                # Handle expiration
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                if datetime.now() > expires_at:
                    print("[WARN][IdentityManager] Expired credentials")
                    return False

                # Secure comparison
                is_valid = encrypted_secret == stored_secret
                print(f"[DEBUG][IdentityManager] Authentication {'success' if is_valid else 'failure'}")
                return is_valid
                
        except Exception as e:
            print(f"[ERROR][IdentityManager] Authentication error: {str(e)}")
            return False

    def get_authorized_peers(self):
        """Get authorized peers list securely"""
        print(f"[DEBUG][IdentityManager] Retrieving authorized peers")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT authorized_peers FROM clients 
                    WHERE client_id = ?
                """, (self.client_id,))
                result = cursor.fetchone()
                
                if result and result[0]:
                    try:
                        return json.loads(result[0])
                    except json.JSONDecodeError:
                        print("[WARN][IdentityManager] Invalid peer list format")
                        return []
                return []
                
        except Exception as e:
            print(f"[ERROR][IdentityManager] Failed to get peers: {str(e)}")
            return []

    def update_authorized_peers(self, peer_list):
        """Update peer list securely"""
        if not isinstance(peer_list, list):
            raise ValueError("Peer list must be an array")
            
        print(f"[DEBUG][IdentityManager] Updating {len(peer_list)} authorized peers")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE clients
                    SET authorized_peers = ?,
                        last_updated = ?
                    WHERE client_id = ?
                """, (
                    json.dumps(peer_list),
                    datetime.now().isoformat(),
                    self.client_id
                ))
                conn.commit()
            return True
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Failed to update peers: {str(e)}")
            raise

    def is_peer_authorized(self, peer_id):
        """Check peer authorization securely"""
        print(f"[DEBUG][IdentityManager] Checking authorization for peer {peer_id[:6]}...")
        return peer_id in self.get_authorized_peers()

    def check_identity_expiration(self, days_before=5):
        """Check identity expiration securely"""
        if not self.is_registered():
            return "not_registered"
            
        identity = self.load_identity()
        if not identity or 'expires_at' not in identity:
            return "invalid"
            
        try:
            expires_at = datetime.fromisoformat(identity['expires_at'])
            remaining = expires_at - datetime.now()

            if remaining.total_seconds() <= 0:
                return "expired"
            elif remaining.total_seconds() <= 1800:  # 30 minutes
                return f"expiring_soon ({int(remaining.total_seconds() // 60)} minutes)"
            elif remaining.days <= days_before:
                return f"expiring_soon ({remaining.days} days)"
            
            return "valid"
            
        except Exception:
            return "invalid"

    def _renew_identity(self):
        """Securely renew identity"""
        print(f"[INFO][IdentityManager] Renewing identity for {self.client_id[:6]}...")
        
        try:
            identity = self.load_identity()
            
            if self.is_expired(identity):
                print("[INFO][IdentityManager] Generating new client identity")
                new_id = f"client_{os.urandom(4).hex()}"
                               
                return IdentityManager(
                    client_id=new_id,
                    client_name=f"Client-{new_id[-4:]}"
                ).register_on_kdc(self.kdc_pub_key)
            

            return self.register_on_kdc(self.kdc_pub_key)
            
        except Exception as e:
            print(f"[ERROR][IdentityManager] Renewal failed: {str(e)}")
            return False


    def authorize_peer(self, peer_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT authorized_peers FROM clients WHERE client_id=?", (self.client_id,))
        current = cursor.fetchone()
        
        if current:
            peers = json.loads(current[0] or "[]")
            if peer_id not in peers:
                peers.append(peer_id)
                cursor.execute(
                    "UPDATE clients SET authorized_peers=? WHERE client_id=?",
                    (json.dumps(peers), self.client_id)
                )
                conn.commit()
