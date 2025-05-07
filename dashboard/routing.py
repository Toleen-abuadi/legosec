from django.urls import path
from . import consumers  # Import your WebSocket consumer

websocket_urlpatterns = [
    path('ws/notifications/<str:client_id>/', consumers.NotificationConsumer.as_asgi()),
]
