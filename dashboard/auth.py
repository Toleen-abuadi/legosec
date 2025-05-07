# dashboard/auth_backends.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from .models import Client
from legosec.identity_manager import IdentityManager
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import json

# dashboard/auth/backends.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from dashboard.models import Client
import binascii

class SecretIdAuthBackend(BaseBackend):
    def authenticate(self, request, client_id=None, encrypted_secret=None):
        try:
            # Get client from database
            client = Client.objects.get(client_id=client_id)
            
            # Convert hex string to bytes if needed
            if isinstance(encrypted_secret, str):
                try:
                    encrypted_secret = binascii.unhexlify(encrypted_secret)
                except binascii.Error:
                    return None
            
            # Debug output - remove in production
            print(f"Client secret from DB: {client.secret_id.hex()}")
            print(f"Provided secret: {encrypted_secret.hex()}")
            
            # Compare the secrets directly
            if client.secret_id == encrypted_secret:
                user, created = get_user_model().objects.get_or_create(username=client_id)
                if created:
                    user.set_unusable_password()
                    user.save()
                return user
                
        except (Client.DoesNotExist, ValueError) as e:
            print(f"Authentication error: {e}")
            return None

    def get_user(self, user_id):
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None