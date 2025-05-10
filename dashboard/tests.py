from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from dashboard.models import Notification, Client
from dashboard.management.commands.check_expiration import Command
from unittest.mock import patch, AsyncMock

class NotificationProcessTest(TestCase):
    def setUp(self):
        # Create a client that will expire soon
        self.client = Client.objects.create(
            client_id='client_1',
            client_name='Test Client',
            secret_id=b'secret_key',
            authorized_peers=[],
            expires_at=timezone.now() + timedelta(days=5),  # Expires in 5 days
            public_key=b'public_key'
        )

    @patch('dashboard.management.commands.check_expiration.get_channel_layer')
    def test_notification_creation_for_expiring_client(self, mock_get_channel_layer):
        # Mock the channel layer
        mock_channel_layer = mock_get_channel_layer.return_value
        mock_channel_layer.group_send = AsyncMock()  # Use AsyncMock for async behavior

        # Run the command to check for expiring identities
        command = Command()
        command.handle()

        # Check if the notification was created
        notification = Notification.objects.filter(client=self.client).first()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, 'EXPIRATION')
        self.assertIn("Your client identity will expire in", notification.message)

    @patch('dashboard.management.commands.check_expiration.get_channel_layer')
    def test_no_notification_for_active_client(self, mock_get_channel_layer):
        # Create another client that is not expiring
        active_client = Client.objects.create(
            client_id='client_2',
            client_name='Active Client',
            secret_id=b'secret_key',
            authorized_peers=[],
            expires_at=timezone.now() + timedelta(days=30),  # Expires in 30 days
            public_key=b'public_key'
        )

        # Mock the channel layer
        mock_channel_layer = mock_get_channel_layer.return_value
        mock_channel_layer.group_send = AsyncMock()  # Use AsyncMock for async behavior

        # Run the command to check for expiring identities
        command = Command()
        command.handle()

        # Check that no notification was created for the active client
        notifications = Notification.objects.filter(client=active_client)
        self.assertEqual(notifications.count(), 0)

    def tearDown(self):
        # Clean up the test data
        Client.objects.all().delete()
        Notification.objects.all().delete()
