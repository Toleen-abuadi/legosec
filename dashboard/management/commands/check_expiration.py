from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from dashboard.models import Notification, Client
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Check for expiring client identities and send notifications'

    def handle(self, *args, **options):
        # Check clients expiring in the next 7 days
        threshold = timezone.now() + timedelta(days=7)
        expiring_clients = Client.objects.filter(
            expires_at__lte=threshold,
            expires_at__gt=timezone.now(),
            is_active=True
        )
        
        channel_layer = get_channel_layer()

        for client in expiring_clients:
            days_remaining = (client.expires_at - timezone.now()).days
            message = f"Your client identity will expire in {days_remaining} days. Please renew it."
            
            # Check if notification already exists
            if not Notification.objects.filter(
                client=client,
                notification_type='EXPIRATION',
                is_read=False,
                message__contains="will expire in"
            ).exists():
                Notification.objects.create(
                    client=client,
                    message=message,
                    notification_type='EXPIRATION',
                    action_url=f"/renew/{client.client_id}/"
                )
                
                # Send notification via WebSocket
                async_to_sync(channel_layer.group_send)(
                    f'notifications_{client.client_id}',
                    {
                        'type': 'send_notification',
                        'message': message
                    }
                )
                self.stdout.write(f"Sent expiration notification to {client.client_id}")
        
        self.stdout.write(self.style.SUCCESS("Expiration check completed"))
