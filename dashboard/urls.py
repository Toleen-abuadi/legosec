# dashboard/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('api/login/', views.api_login, name='api-login'),


    path('dashboard/<str:client_id>/', views.client_dashboard, name='client-dashboard'),
    path('notifications/', views.notification_list, name='notification-list'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),  # Using built-in LogoutView
    path('renew/<str:client_id>/', views.renew_identity, name='renew-identity'),
]