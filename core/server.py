import socket
import threading
import os
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import padding
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

    def _generate_private_key(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def _derive_symmetric_key(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-channel-key',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def _encrypt_with_key(self, key, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def handle_client(self, client_sock, addr):
        print(f"[KDC] Client connected from {addr}")
        try:
            # Step 1: Send public key
            client_sock.sendall(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

            # Step 2: Receive encrypted param
            encrypted_param = client_sock.recv(4096)
            client_param = self.private_key.decrypt(
                encrypted_param,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Step 3: Derive symmetric key
            symmetric_key = self._derive_symmetric_key(client_param)

            # Step 4: Send encrypted server param
            kdc_param = os.urandom(32)
            encrypted_kdc_param = self._encrypt_with_key(symmetric_key, kdc_param)
            client_sock.sendall(encrypted_kdc_param)

            print("[KDC] Secure key exchange complete with client.")
            # Registration/authentication could go here as phase 2

        except Exception as e:
            print(f"[KDC] Error handling client: {e}")
        finally:
            client_sock.close()

    def start(self):
        print(f"[KDC] Starting KDC server on {self.host}:{self.port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while True:
                client_sock, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()

if __name__ == '__main__':
    server = KDCServer()
    server.start()