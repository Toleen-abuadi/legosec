from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid
import json

class Client(models.Model):
    """Represents a registered client in the system"""
    client_id = models.CharField(max_length=64, primary_key=True, unique=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    encrypted_secret = models.BinaryField()
    public_key = models.BinaryField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'clients'
        ordering = ['-created_at']
        verbose_name = 'Client'
        verbose_name_plural = 'Clients'

    def __str__(self):
        return f"{self.name or 'Anonymous'} ({self.client_id})"

    def is_expired(self):
        return timezone.now() > self.expires_at
    is_expired.boolean = True

    def get_authorized_peers(self):
        """Get list of authorized peer IDs"""
        auths = Authorization.objects.filter(client=self, is_active=True)
        return [auth.authorized_client.client_id for auth in auths]

    def add_authorized_peer(self, peer_id):
        """Authorize a new peer"""
        peer = Client.objects.get(client_id=peer_id)
        Authorization.objects.get_or_create(
            client=self,
            authorized_client=peer,
            defaults={'is_active': True}
        )


class Authorization(models.Model):
    """Defines which clients can communicate with each other"""
    client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='outgoing_authorizations'
    )
    authorized_client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='incoming_authorizations'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'authorizations'
        unique_together = ('client', 'authorized_client')
        verbose_name = 'Authorization'
        verbose_name_plural = 'Authorizations'

    def __str__(self):
        return f"{self.client} → {self.authorized_client}"


class SessionKey(models.Model):
    """Tracks active session keys between clients"""
    key_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    initiator = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='initiated_sessions'
    )
    responder = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='responded_sessions'
    )
    session_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'session_keys'
        ordering = ['-created_at']
        verbose_name = 'Session Key'
        verbose_name_plural = 'Session Keys'

    def __str__(self):
        return f"Session {self.key_id} ({self.initiator} ↔ {self.responder})"

    def is_expired(self):
        return timezone.now() > self.expires_at
    is_expired.boolean = True


class ConnectionLog(models.Model):
    """Logs all connection attempts and system events"""
    CONNECTION_TYPES = [
        ('KDC', 'KDC Authentication'),
        ('P2P', 'Peer-to-Peer'),
        ('REG', 'Registration'),
        ('AUTH', 'Authorization'),
        ('KEY', 'Key Exchange'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
    ]

    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connection_type = models.CharField(max_length=4, choices=CONNECTION_TYPES)
    initiator = models.ForeignKey(
        Client,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='initiated_connections'
    )
    target = models.ForeignKey(
        Client,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='received_connections'
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=7, choices=STATUS_CHOICES)
    details = models.TextField(blank=True)
    session_key = models.ForeignKey(
        SessionKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    duration = models.FloatField(blank=True, null=True)  # Duration in seconds

    class Meta:
        db_table = 'connection_logs'
        ordering = ['-timestamp']
        verbose_name = 'Connection Log'
        verbose_name_plural = 'Connection Logs'

    def __str__(self):
        return f"{self.get_connection_type_display()} - {self.initiator or 'System'} to {self.target or 'System'} ({self.get_status_display()})"


class SystemParameter(models.Model):
    """Stores configurable system parameters"""
    PARAM_TYPES = [
        ('INT', 'Integer'),
        ('STR', 'String'),
        ('BOOL', 'Boolean'),
        ('JSON', 'JSON'),
    ]

    name = models.CharField(max_length=50, unique=True)
    param_type = models.CharField(max_length=4, choices=PARAM_TYPES)
    value = models.TextField()
    description = models.TextField(blank=True)
    last_modified = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'system_parameters'
        verbose_name = 'System Parameter'
        verbose_name_plural = 'System Parameters'

    def __str__(self):
        return f"{self.name} ({self.get_param_type_display()})"

    def get_typed_value(self):
        if self.param_type == 'INT':
            return int(self.value)
        elif self.param_type == 'BOOL':
            return self.value.lower() in ('true', '1', 'yes')
        elif self.param_type == 'JSON':
            return json.loads(self.value)
        return self.value