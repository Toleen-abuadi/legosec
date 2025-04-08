from django.urls import path
from .views import (
    DashboardView, ClientListView, ClientDetailView, ClientCreateView,
    SessionKeyListView, ConnectionLogListView, SystemSettingsView,
    AuthorizationCreateView
)

urlpatterns = [
    path('', DashboardView.as_view(), name='dashboard'),
    path('clients/', ClientListView.as_view(), name='client_list'),
    path('clients/<uuid:client_id>/', ClientDetailView.as_view(), name='client_detail'),
    path('clients/add/', ClientCreateView.as_view(), name='client_create'),
    path('sessions/', SessionKeyListView.as_view(), name='session_list'),
    path('connections/', ConnectionLogListView.as_view(), name='connection_list'),
    path('settings/', SystemSettingsView.as_view(), name='system_settings'),
    path('authorizations/add/', AuthorizationCreateView.as_view(), name='authorization_create'),
]