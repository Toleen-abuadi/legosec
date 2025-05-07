import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from .models import Client

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.client_id = self.scope['url_route']['kwargs']['client_id']
        self.group_name = f'notifications_{self.client_id}'

        # Verify client exists
        client_exists = await sync_to_async(Client.objects.filter(client_id=self.client_id).exists)()
        if not client_exists:
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Handle incoming messages if needed
        pass

    async def send_notification(self, event):
        # Send notification to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'title': event.get('title', 'Notification'),
            'message': event['message'],
            'action_url': event.get('action_url'),
            'timestamp': event.get('timestamp'),
        }))
        
    async def status_update(self, event):
        # Send status updates to client
        await self.send(text_data=json.dumps({
            'type': 'status_update',
            'status': event['status'],
            'expires_at': event['expires_at'],
        }))