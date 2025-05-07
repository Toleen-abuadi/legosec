from django.db import models
import json
from django.utils import timezone

class Client(models.Model):
    client_id = models.CharField(max_length=100, primary_key=True)
    client_name = models.CharField(max_length=100)
    secret_id = models.BinaryField()
    authorized_peers = models.JSONField(default=list)  # Matches the KDC's authorized_peers
    expires_at = models.DateTimeField()  # Matches KDC field name
    public_key = models.BinaryField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return f"{self.client_name} ({self.client_id})"

    def status(self):
        if self.expires_at < timezone.now():
            return "Expired"
        elif (self.expires_at - timezone.now()).days <= 7:
            return f"Expiring soon ({(self.expires_at - timezone.now()).days} days)"
        return "Active"
    
    class Meta:
        db_table = 'clients'


class PSKExchange(models.Model):
    from_client = models.ForeignKey(Client, related_name='outgoing_psks', on_delete=models.CASCADE)
    to_client = models.ForeignKey(Client, related_name='incoming_psks', on_delete=models.CASCADE)
    shared_psk = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('from_client', 'to_client')
        db_table = 'psk_exchange'

    def __str__(self):
        return f"PSK: {self.from_client} → {self.to_client}"


class SessionKey(models.Model):
    session_id = models.CharField(max_length=100, primary_key=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    session_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"Session {self.session_id} for {self.client}"
    
    class Meta:
        db_table = 'session_keys'
        


class Notification(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=[
        ('EXPIRATION', 'Identity Expiration'),
        ('NEW_PEER', 'New Peer Authorization'),
        ('PSK_UPDATE', 'PSK Updated'),
        ('SYSTEM', 'System Message'),
    ])
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    action_url = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return f"Notification for {self.client}: {self.message[:50]}..."
    
    class Meta:
        db_table = 'notifications'


class ClientLog(models.Model):
    LOG_TYPES = (
        ('AUTH', 'Authentication'),
        ('CONN', 'Connection'),
        ('PSK', 'Key Exchange'),
        ('REG', 'Registration'),
        ('ERR', 'Error'),
    )

    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    log_type = models.CharField(max_length=4, choices=LOG_TYPES)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.timestamp} [{self.get_log_type_display()}] {self.message}"
    
    class Meta:
        db_table = 'client_logs'
