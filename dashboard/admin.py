# dashboard/admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Client, PSKExchange, SessionKey, Notification, ClientLog
from django.utils import timezone
import binascii
import json

# Helper functions
def hex_display(binary_data, length=20):
    """Display binary data as truncated hex"""
    if not binary_data:
        return "-"
    hex_str = binascii.hexlify(binary_data).decode('utf-8')
    return f"{hex_str[:length]}..." if len(hex_str) > length else hex_str

def time_remaining(obj):
    """Display time remaining for expiration"""
    if obj.expires_at:
        delta = obj.expires_at - timezone.now()
        if delta.days < 0:
            return "Expired"
        return f"{delta.days} days, {delta.seconds//3600} hours"
    return "-"

# ModelAdmins
@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = (
        'client_id', 
        'client_name', 
        'status_display',
        'expires_at_display',
        'time_remaining',
        'last_updated',
    )
    list_filter = ('expires_at', 'last_updated')
    search_fields = ('client_id', 'client_name')
    readonly_fields = (
        'status_display',
        'time_remaining',
        'secret_id_display',
        'public_key_display',
        'authorized_peers_display',
    )
    fieldsets = (
        ('Identification', {
            'fields': ('client_id', 'client_name')
        }),
        ('Security', {
            'fields': (
                'secret_id_display', 
                'public_key_display',
                'authorized_peers_display',
            )
        }),
        ('Validity', {
            'fields': (
                'expires_at',
                'status_display',
                'time_remaining',
                'last_updated',
            )
        }),
    )

    def status_display(self, obj):
        return obj.status()
    status_display.short_description = 'Status'

    def expires_at_display(self, obj):
        return obj.expires_at.strftime("%Y-%m-%d %H:%M")
    expires_at_display.short_description = 'Expires At'
    expires_at_display.admin_order_field = 'expires_at'

    def time_remaining(self, obj):
        return time_remaining(obj)
    time_remaining.short_description = 'Time Remaining'

    def secret_id_display(self, obj):
        return hex_display(obj.secret_id)
    secret_id_display.short_description = 'Secret ID'

    def public_key_display(self, obj):
        return hex_display(obj.public_key)
    public_key_display.short_description = 'Public Key'

    def authorized_peers_display(self, obj):
        if not obj.authorized_peers:
            return "-"
        links = []
        for peer_id in obj.authorized_peers:
            url = reverse('admin:dashboard_client_change', args=[peer_id])
            links.append(f'<a href="{url}">{peer_id}</a>')
        return format_html(", ".join(links))
    authorized_peers_display.short_description = 'Authorized Peers'


class PSKExchangeInline(admin.TabularInline):
    model = PSKExchange
    fk_name = 'from_client'
    extra = 0
    readonly_fields = ('psk_display', 'created_at')
    fields = ('to_client', 'psk_display', 'created_at')

    def psk_display(self, obj):
        return hex_display(obj.shared_psk)
    psk_display.short_description = 'PSK'


@admin.register(PSKExchange)
class PSKExchangeAdmin(admin.ModelAdmin):
    list_display = (
        'from_client',
        'to_client',
        'psk_display',
        'created_at',
    )
    list_filter = ('created_at', 'from_client', 'to_client')
    search_fields = (
        'from_client__client_id',
        'to_client__client_id',
    )
    readonly_fields = ('psk_display',)

    def psk_display(self, obj):
        return hex_display(obj.shared_psk)
    psk_display.short_description = 'PSK'


@admin.register(SessionKey)
class SessionKeyAdmin(admin.ModelAdmin):
    list_display = (
        'session_id',
        'client_link',
        'key_display',
        'created_at',
        'expires_at_display',
        'time_remaining',
    )
    list_filter = ('created_at', 'expires_at', 'client')
    search_fields = ('session_id', 'client__client_id')
    readonly_fields = ('key_display', 'time_remaining')

    def client_link(self, obj):
        url = reverse('admin:dashboard_client_change', args=[obj.client.client_id])
        return format_html('<a href="{}">{}</a>', url, obj.client)
    client_link.short_description = 'Client'
    client_link.admin_order_field = 'client'

    def key_display(self, obj):
        return hex_display(obj.session_key)
    key_display.short_description = 'Session Key'

    def expires_at_display(self, obj):
        return obj.expires_at.strftime("%Y-%m-%d %H:%M")
    expires_at_display.short_description = 'Expires At'
    expires_at_display.admin_order_field = 'expires_at'

    def time_remaining(self, obj):
        return time_remaining(obj)
    time_remaining.short_description = 'Time Remaining'


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = (
        'client_link',
        'short_message',
        'notification_type',
        'is_read',
        'created_at',
    )
    list_filter = ('notification_type', 'is_read', 'created_at')
    search_fields = ('client__client_id', 'message')
    readonly_fields = ('created_at',)
    list_editable = ('is_read',)

    def client_link(self, obj):
        url = reverse('admin:dashboard_client_change', args=[obj.client.client_id])
        return format_html('<a href="{}">{}</a>', url, obj.client)
    client_link.short_description = 'Client'
    client_link.admin_order_field = 'client'

    def short_message(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    short_message.short_description = 'Message'


@admin.register(ClientLog)
class ClientLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp',
        'client_link',
        'log_type_display',
        'short_message',
    )
    list_filter = ('log_type', 'timestamp')
    search_fields = ('client__client_id', 'message')
    readonly_fields = ('metadata_display',)

    def client_link(self, obj):
        url = reverse('admin:dashboard_client_change', args=[obj.client.client_id])
        return format_html('<a href="{}">{}</a>', url, obj.client)
    client_link.short_description = 'Client'
    client_link.admin_order_field = 'client'

    def log_type_display(self, obj):
        return obj.get_log_type_display()
    log_type_display.short_description = 'Type'

    def short_message(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    short_message.short_description = 'Message'

    def metadata_display(self, obj):
        return format_html("<pre>{}</pre>", json.dumps(obj.metadata, indent=2))
    metadata_display.short_description = 'Metadata'