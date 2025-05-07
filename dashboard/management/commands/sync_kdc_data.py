# dashboard/management/commands/sync_kdc_data.py
from django.core.management.base import BaseCommand
from dashboard.models import Client, PSKExchange, ClientLog
import sqlite3
from django.utils import timezone
import json

class Command(BaseCommand):
    help = 'Sync data from KDC SQLite database to Django models'

    def handle(self, *args, **options):
        self.stdout.write("Starting KDC data sync...")
        
        # Connect to KDC SQLite database
        kdc_db = sqlite3.connect('kdc_database.db')
        kdc_cursor = kdc_db.cursor()
        
        # Sync Clients
        kdc_cursor.execute("SELECT client_id, client_name, secret_id, authorized_peers, expires_at, public_key FROM clients")
        for row in kdc_cursor.fetchall():
            client_id, client_name, secret_id, authorized_peers_json, expires_at, public_key = row
            
            # Convert authorized_peers from JSON string to list
            try:
                authorized_peers = json.loads(authorized_peers_json)
            except:
                authorized_peers = []
                
            Client.objects.update_or_create(
                client_id=client_id,
                defaults={
                    'client_name': client_name,
                    'secret_id': secret_id,
                    'authorized_peers': authorized_peers,
                    'expires_at': expires_at,
                    'public_key': public_key,
                }
            )
        
        # Sync PSK Exchanges
        kdc_cursor.execute("SELECT from_id, to_id, shared_psk FROM psk_exchange")
        for row in kdc_cursor.fetchall():
            from_id, to_id, shared_psk = row
            
            try:
                from_client = Client.objects.get(client_id=from_id)
                to_client = Client.objects.get(client_id=to_id)
                
                PSKExchange.objects.update_or_create(
                    from_client=from_client,
                    to_client=to_client,
                    defaults={'shared_psk': shared_psk}
                )
            except Client.DoesNotExist:
                continue
        
        self.stdout.write(self.style.SUCCESS("KDC data sync completed successfully"))