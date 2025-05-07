from django.core.management.base import BaseCommand
from dashboard.models import Client

class Command(BaseCommand):
    help = 'List all clients in database'

    def handle(self, *args, **options):
        for client in Client.objects.all():
            self.stdout.write(f"{client.client_id}: {client.client_name}")
            self.stdout.write(f"Secret: {client.secret_id.hex()[:30]}...")