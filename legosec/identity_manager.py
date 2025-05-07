import os
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Register SQLite3 datetime handlers (Python 3.12+ compatibility)
sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda s: datetime.fromisoformat(s.decode()))

class IdentityManager:
    def __init__(self, client_id=None, client_name=None, identity_dir=".", db_path="../kdc_database.db"):
        self.client_id = client_id or f"client_{os.urandom(4).hex()}"  # Auto-generated if not provided
        self.client_name = client_name or f"Client-{self.client_id[-4:]}"  # Default name
        self.identity_path = Path(identity_dir) / f".{self.client_id}_identity.json"
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize the database with required tables"""
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

    def is_registered(self):
        """Check if client is registered by verifying identity file exists"""
        return self.identity_path.exists()

    def load_identity(self):
        """Load identity data from JSON file"""
        if not self.is_registered():
            return None
            
        try:
            with open(self.identity_path, 'r') as f:
                data = json.load(f)
                # Validate required fields
                if all(key in data for key in ['client_id', 'client_name', 'encrypted_secret', 'expires_at']):
                    return data
                return None
        except (json.JSONDecodeError, IOError):
            return None

    def is_expired(self, identity_data):
        """Check if identity has expired"""
        if not identity_data or 'expires_at' not in identity_data:
            return True
            
        try:
            expires_at = datetime.fromisoformat(identity_data['expires_at'])
            return datetime.now() > expires_at
        except ValueError:
            return True

    def store_identity(self, encrypted_secret, expires_at):
        """Store identity information in JSON file"""
        data = {
            'client_id': self.client_id,
            'client_name': self.client_name,
            'encrypted_secret': encrypted_secret.hex(),
            'expires_at': expires_at.isoformat(),
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            with open(self.identity_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except IOError:
            return False

    def register_on_kdc(self, kdc_public_key):
        """Register client with KDC and store identity"""
        secret = os.urandom(32)  # Generate client secret
        expires_at = datetime.now() + timedelta(hours=3)  # 30-day validity

        # Encrypt secret with KDC's public key
        encrypted_secret = kdc_public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Store in database
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
                json.dumps([]),  # Empty authorized peers list
                expires_at.isoformat()
            ))
            conn.commit()

        # Store local identity file
        if self.store_identity(encrypted_secret, expires_at):
            print(f"[REGISTER] {self.client_name} (ID: {self.client_id}) registered and identity stored.")
            return True
        return False

    def authenticate_with_kdc(self, encrypted_secret):
        """Authenticate client with KDC using stored secret"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT secret_id, expires_at FROM clients 
                WHERE client_id = ?
            """, (self.client_id,))
            result = cursor.fetchone()

            if not result:
                return False

            stored_secret, expires_at = result

            try:
                # Handle both string and datetime expires_at
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                
                if datetime.now() > expires_at:
                    return False

                return encrypted_secret == stored_secret
            except (ValueError, TypeError):
                return False

    def get_authorized_peers(self):
        """Get list of authorized peers for this client"""
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
                    return []
            return []

    def update_authorized_peers(self, peer_list):
        """Update authorized peers list for this client"""
        if not isinstance(peer_list, list):
            raise ValueError("peer_list must be a list")
            
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

    def is_peer_authorized(self, peer_id):
        """Check if peer is authorized for this client"""
        authorized = self.get_authorized_peers()
        return peer_id in authorized

    def check_identity_expiration(self):
        """Check identity status without side effects"""
        status = self._get_identity_status()
        if status == "expired":
            return "expired"
        elif status == "not_found":
            return "not_registered"
        elif status == "expiring_soon":
            return f"expiring_soon ({self._get_days_until_expiry()} days)"
        return "valid"

    def renew_identity(self, kdc_public_key=None, auto_renew=False):
        """Handle the security aspects of identity renewal"""
        if not auto_renew and self._get_identity_status() not in ["expired", "expiring_soon"]:
            return False

        # 1. Generate new secret and expiry
        secret = os.urandom(32)
        new_expiry = datetime.now() + timedelta(days=30)
        
        # 2. Encrypt with KDC's public key if provided
        if kdc_public_key:
            encrypted_secret = kdc_public_key.encrypt(
                secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else:
            # Try to get from existing identity
            identity = self.load_identity()
            if not identity:
                return False
            encrypted_secret = bytes.fromhex(identity['encrypted_secret'])

        # 3. Update database and local file
        success = self._update_client_identity(encrypted_secret, new_expiry)
        if success:
            self.store_identity(encrypted_secret, new_expiry)
        return success

    # Private helper methods
    def _get_identity_status(self):
        """Internal method to check identity status"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT expires_at FROM clients WHERE client_id = ?
            """, (self.client_id,))
            result = cursor.fetchone()
            
            if not result:
                return "not_found"
                
            expires_at = result[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
                
            if datetime.now() > expires_at:
                return "expired"
            elif (expires_at - datetime.now()).days <= 1:
                return "expiring_soon"
            return "valid"

    def _get_days_until_expiry(self):
        """Get days until identity expires"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT expires_at FROM clients WHERE client_id = ?
            """, (self.client_id,))
            result = cursor.fetchone()
            expires_at = result[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            return (expires_at - datetime.now()).days

    def _update_client_identity(self, encrypted_secret, expires_at):
        """Update client record in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE clients 
                SET secret_id = ?, expires_at = ?, last_updated = ?
                WHERE client_id = ?
            """, (
                encrypted_secret,
                expires_at.isoformat(),
                datetime.now().isoformat(),
                self.client_id
            ))
            conn.commit()
            return cursor.rowcount > 0

    def get_last_updated(self):
        """Get the last updated timestamp for this client"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT last_updated FROM clients 
                WHERE client_id = ?
            """, (self.client_id,))
            result = cursor.fetchone()
            
            if result and result[0]:
                if isinstance(result[0], str):
                    return datetime.fromisoformat(result[0])
                return result[0]
            return None