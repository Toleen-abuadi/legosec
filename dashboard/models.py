from django.db import models
from django.utils import timezone
from django.core.validators import MinLengthValidator
import uuid

class Client(models.Model):
    """
    Represents a client registered with the KDC
    """
    identifier = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Client ID"
    )
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Optional human-readable name"
    )
    encrypted_secret = models.TextField(
        verbose_name="Encrypted Secret ID",
        help_text="Secret ID encrypted with KDC's public key"
    )
    public_key = models.TextField(
        blank=True,
        null=True,
        verbose_name="Client Public Key",
        help_text="Client's public key if available"
    )
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name="Last Known IP"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Active Status"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Registration Date"
    )
    expires_at = models.DateTimeField(
        verbose_name="Expiration Date"
    )
    last_accessed = models.DateTimeField(
        auto_now=True,
        verbose_name="Last Access"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Registered Client"
        verbose_name_plural = "Registered Clients"

    def __str__(self):
        return f"{self.name or 'Anonymous'} ({self.identifier})"

    def is_expired(self):
        return timezone.now() > self.expires_at
    is_expired.boolean = True
    is_expired.short_description = "Expired"


class Authorization(models.Model):
    """
    Defines which clients are authorized to connect to each other
    """
    client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='outgoing_authorizations',
        verbose_name="Source Client"
    )
    authorized_client = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='incoming_authorizations',
        verbose_name="Authorized Client"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Authorization Date"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Active"
    )

    class Meta:
        unique_together = ('client', 'authorized_client')
        verbose_name = "Client Authorization"
        verbose_name_plural = "Client Authorizations"
        ordering = ['client', 'authorized_client']

    def __str__(self):
        return f"{self.client} → {self.authorized_client}"


class SessionKey(models.Model):
    """
    Stores session keys distributed by the KDC
    """
    key_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        verbose_name="Key ID"
    )
    initiator = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='initiated_sessions',
        verbose_name="Initiator Client"
    )
    responder = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='responded_sessions',
        verbose_name="Responder Client"
    )
    session_key = models.TextField(
        verbose_name="Encrypted Session Key"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Creation Time"
    )
    expires_at = models.DateTimeField(
        verbose_name="Expiration Time"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Active"
    )

    class Meta:
        verbose_name = "Session Key"
        verbose_name_plural = "Session Keys"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['initiator', 'responder']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"Session {self.key_id} ({self.initiator} ↔ {self.responder})"

    def is_expired(self):
        return timezone.now() > self.expires_at
    is_expired.boolean = True
    is_expired.short_description = "Expired"


class ConnectionLog(models.Model):
    """
    Logs all connection attempts and established connections
    """
    CONNECTION_TYPES = [
        ('KDC', 'KDC Authentication'),
        ('P2P', 'Peer-to-Peer'),
        ('REG', 'Registration'),
        ('AUTH', 'Authorization Check'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
        ('TIMEOUT', 'Timeout'),
    ]

    log_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        verbose_name="Log ID"
    )
    connection_type = models.CharField(
        max_length=4,
        choices=CONNECTION_TYPES,
        verbose_name="Connection Type"
    )
    initiator = models.ForeignKey(
        Client,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='initiated_connections',
        verbose_name="Initiator"
    )
    target = models.ForeignKey(
        Client,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='received_connections',
        verbose_name="Target"
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Timestamp"
    )
    status = models.CharField(
        max_length=7,
        choices=STATUS_CHOICES,
        verbose_name="Status"
    )
    details = models.TextField(
        blank=True,
        verbose_name="Additional Details"
    )
    session_key_ref = models.ForeignKey(
        SessionKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Associated Session Key"
    )
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name="IP Address"
    )
    duration = models.DurationField(
        blank=True,
        null=True,
        verbose_name="Connection Duration"
    )

    class Meta:
        verbose_name = "Connection Log"
        verbose_name_plural = "Connection Logs"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['connection_type']),
            models.Index(fields=['status']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.get_connection_type_display()} - {self.initiator or 'System'} to {self.target or 'System'} ({self.get_status_display()})"


class SystemParameter(models.Model):
    """
    Stores system-wide parameters and configurations
    """
    PARAM_TYPES = [
        ('INT', 'Integer'),
        ('STR', 'String'),
        ('BOOL', 'Boolean'),
        ('JSON', 'JSON'),
    ]

    name = models.CharField(
        max_length=50,
        unique=True,
        verbose_name="Parameter Name"
    )
    param_type = models.CharField(
        max_length=4,
        choices=PARAM_TYPES,
        verbose_name="Parameter Type"
    )
    value = models.TextField(
        verbose_name="Parameter Value"
    )
    description = models.TextField(
        blank=True,
        verbose_name="Description"
    )
    last_modified = models.DateTimeField(
        auto_now=True,
        verbose_name="Last Modified"
    )

    class Meta:
        verbose_name = "System Parameter"
        verbose_name_plural = "System Parameters"
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.get_param_type_display()})"

    def get_typed_value(self):
        if self.param_type == 'INT':
            return int(self.value)
        elif self.param_type == 'BOOL':
            return self.value.lower() in ('true', '1', 'yes')
        elif self.param_type == 'JSON':
            import json
            return json.loads(self.value)
        return self.value