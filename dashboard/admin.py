from django.contrib import admin
from .models import Client, Authorization, SessionKey, ConnectionLog, SystemParameter

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('identifier', 'name', 'ip_address', 'is_active', 'created_at', 'expires_at', 'is_expired')
    list_filter = ('is_active', 'created_at')
    search_fields = ('identifier', 'name', 'ip_address')
    readonly_fields = ('created_at', 'last_accessed')

@admin.register(Authorization)
class AuthorizationAdmin(admin.ModelAdmin):
    list_display = ('client', 'authorized_client', 'created_at', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('client__identifier', 'authorized_client__identifier')

@admin.register(SessionKey)
class SessionKeyAdmin(admin.ModelAdmin):
    list_display = ('key_id', 'initiator', 'responder', 'created_at', 'expires_at', 'is_active', 'is_expired')
    list_filter = ('is_active', 'created_at')
    search_fields = ('key_id', 'initiator__identifier', 'responder__identifier')

@admin.register(ConnectionLog)
class ConnectionLogAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'connection_type', 'initiator', 'target', 'timestamp', 'status', 'ip_address')
    list_filter = ('connection_type', 'status', 'timestamp')
    search_fields = ('log_id', 'initiator__identifier', 'target__identifier', 'ip_address')
    readonly_fields = ('timestamp',)

@admin.register(SystemParameter)
class SystemParameterAdmin(admin.ModelAdmin):
    list_display = ('name', 'param_type', 'last_modified')
    list_filter = ('param_type',)
    search_fields = ('name', 'description')