from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.views.generic import ListView, DetailView
from django.contrib import messages
from django.db.models import Q
from .models import Client, Authorization, SessionKey, ConnectionLog, SystemParameter
from .forms import ClientForm, AuthorizationForm, SystemParameterForm
import json
from django.utils import timezone
from datetime import timedelta


class DashboardView(View):
    template_name = 'dashboard/index.html'
    
    def get(self, request):
        # Get statistics
        total_clients = Client.objects.count()
        active_clients = Client.objects.filter(is_active=True).count()
        expired_clients = Client.objects.filter(expires_at__lt=timezone.now()).count()
        
        # Get recent activity
        recent_connections = ConnectionLog.objects.all().order_by('-timestamp')[:10]
        recent_sessions = SessionKey.objects.filter(is_active=True).order_by('-created_at')[:5]
        
        context = {
            'total_clients': total_clients,
            'active_clients': active_clients,
            'expired_clients': expired_clients,
            'recent_connections': recent_connections,
            'recent_sessions': recent_sessions,
        }
        return render(request, self.template_name, context)

class ClientListView(ListView):
    model = Client
    template_name = 'dashboard/client_list.html'
    context_object_name = 'clients'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = super().get_queryset()
        search_query = self.request.GET.get('q')
        
        if search_query:
            queryset = queryset.filter(
                Q(identifier__icontains=search_query) |
                Q(name__icontains=search_query) |
                Q(ip_address__icontains=search_query)
            )
        
        return queryset.order_by('-created_at')

class ClientDetailView(DetailView):
    model = Client
    template_name = 'dashboard/client_detail.html'
    context_object_name = 'client'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        client = self.get_object()
        
        # Add related data to context
        context['authorizations'] = Authorization.objects.filter(client=client)
        context['initiated_sessions'] = SessionKey.objects.filter(initiator=client)
        context['received_sessions'] = SessionKey.objects.filter(responder=client)
        context['connections'] = ConnectionLog.objects.filter(
            Q(initiator=client) | Q(target=client)
        ).order_by('-timestamp')[:20]
        
        return context

class ClientCreateView(View):
    template_name = 'dashboard/client_form.html'
    
    def get(self, request):
        form = ClientForm()
        return render(request, self.template_name, {'form': form})
    
    def post(self, request):
        form = ClientForm(request.POST)
        if form.is_valid():
            client = form.save(commit=False)
            client.created_at = timezone.now()
            client.expires_at = timezone.now() + timedelta(days=30)  # Default 30-day expiry
            client.save()
            
            # Log the creation
            ConnectionLog.objects.create(
                connection_type='REG',
                status='SUCCESS',
                details=f"New client created via dashboard: {client.identifier}",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Client created successfully!')
            return redirect('client_detail', client_id=client.identifier)
        
        return render(request, self.template_name, {'form': form})

class SessionKeyListView(ListView):
    model = SessionKey
    template_name = 'dashboard/session_list.html'
    context_object_name = 'sessions'
    paginate_by = 20
    
    def get_queryset(self):
        return SessionKey.objects.all().order_by('-created_at')

class ConnectionLogListView(ListView):
    model = ConnectionLog
    template_name = 'dashboard/connection_list.html'
    context_object_name = 'connections'
    paginate_by = 50
    
    def get_queryset(self):
        queryset = super().get_queryset()
        connection_type = self.request.GET.get('type')
        status = self.request.GET.get('status')
        
        if connection_type:
            queryset = queryset.filter(connection_type=connection_type)
        if status:
            queryset = queryset.filter(status=status)
        
        return queryset.order_by('-timestamp')

class SystemSettingsView(View):
    template_name = 'dashboard/settings.html'
    
    def get(self, request):
        parameters = SystemParameter.objects.all().order_by('name')
        form = SystemParameterForm()
        return render(request, self.template_name, {
            'parameters': parameters,
            'form': form
        })
    
    def post(self, request):
        form = SystemParameterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Parameter added successfully!')
            return redirect('system_settings')
        
        parameters = SystemParameter.objects.all().order_by('name')
        return render(request, self.template_name, {
            'parameters': parameters,
            'form': form
        })

class AuthorizationCreateView(View):
    template_name = 'dashboard/authorization_form.html'
    
    def get(self, request):
        form = AuthorizationForm()
        return render(request, self.template_name, {'form': form})
    
    def post(self, request):
        form = AuthorizationForm(request.POST)
        if form.is_valid():
            authorization = form.save()
            
            # Log the authorization
            ConnectionLog.objects.create(
                connection_type='AUTH',
                initiator=authorization.client,
                target=authorization.authorized_client,
                status='SUCCESS',
                details=f"Authorization created: {authorization.client} → {authorization.authorized_client}",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Authorization created successfully!')
            return redirect('client_detail', client_id=authorization.client.identifier)
        
        return render(request, self.template_name, {'form': form})