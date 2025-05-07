"""
ASGI config for dashboard project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""


from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path
from dashboard.consumers import NotificationConsumer

application = ProtocolTypeRouter({
    "websocket": URLRouter([
        path("ws/notifications/<str:client_id>/", NotificationConsumer.as_asgi()),
    ]),
})

