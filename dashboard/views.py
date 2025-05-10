from django.shortcuts import render, get_object_or_404, redirect
import json
from django.contrib.auth.decorators import login_required
from django.db import models, transaction
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.urls import reverse
from .models import Client, ClientLog, Notification, PSKExchange
from legosec.identity_manager import IdentityManager
from django.contrib.auth import logout

@ensure_csrf_cookie
def login_view(request):
    if request.user.is_authenticated:
        return redirect('client-dashboard', client_id=request.user.username)
    return render(request, 'login.html')

@require_POST
def logout_view(request):
    logout(request)
    return JsonResponse({'status': 'success', 'redirect_url': reverse('login')})


def api_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            client_id = data.get('client_id')
            encrypted_secret = data.get('encrypted_secret')
            
            print(f"Login attempt - Client ID: {client_id}, Secret: {encrypted_secret[:20]}...")  # Debug
            
            if not (client_id and encrypted_secret):
                return JsonResponse(
                    {'error': 'client_id and encrypted_secret required'},
                    status=400
                )
                
            user = authenticate(
                request,
                client_id=client_id,
                encrypted_secret=encrypted_secret
            )
            
            if user is not None:
                login(request, user)
                return JsonResponse({
                    'status': 'authenticated',
                    'client_id': client_id,
                    'redirect_url': reverse('client-dashboard', kwargs={'client_id': client_id})
                })
            else:
                print("Authentication failed - invalid credentials")
                return JsonResponse({'error': 'Invalid credentials'}, status=401)
                
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            print(f"Login error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def client_dashboard(request, client_id):
    """Main dashboard view with client status and notifications"""
    client = get_object_or_404(Client, client_id=client_id)
    
    # Check for expiring identity and create notification if needed
    check_identity_expiration(client)
    
    context = {
        'client': client,
        'notifications': get_unread_notifications(client_id),
        'status': get_client_status(client_id),
        'logs': get_recent_logs(client_id),
    }
    return render(request, 'dashboard.html', context)

@login_required
@require_POST
def mark_notification_read(request, notification_id):
    """Mark a single notification as read"""
    with transaction.atomic():
        notification = get_object_or_404(
            Notification, 
            id=notification_id,
            client__client_id=request.user.username
        )
        notification.is_read = True
        notification.save()
        
        log_client_activity(
            client_id=request.user.username,
            log_type='NOTIFICATION',
            message=f'Marked notification {notification_id} as read'
        )
        
    return JsonResponse({'status': 'success'})

@login_required
@require_POST
def mark_all_notifications_read(request):
    """Mark all notifications as read for this client"""
    with transaction.atomic():
        updated = Notification.objects.filter(
            client__client_id=request.user.username,
            is_read=False
        ).update(is_read=True)
        
        log_client_activity(
            client_id=request.user.username,
            log_type='NOTIFICATION',
            message=f'Marked {updated} notifications as read'
        )
        
    return JsonResponse({'status': 'success', 'marked_read': updated})

@login_required
@require_POST
def renew_identity(request, client_id):
    print(f"\n=== Renew Identity Request ===")
    print(f"Client ID: {client_id}")
    print(f"User: {request.user.username}")
    print(f"Method: {request.method}")
    print(f"Headers: {request.headers}")
    print("Body:", request.body)
    
    if request.user.username != client_id:
        print("Authorization failed")
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        print("Initializing IdentityManager...")
        im = IdentityManager(client_id=client_id)
        status = im.check_identity_expiration()
        print(f"Current status: {status}")
        
        if status == "not_registered":
            print("Client not registered")
            return JsonResponse({'error': 'Client not registered'}, status=400)
            
        print("Attempting renewal...")
        if not im.renew_identity():
            raise Exception("Renewal failed")
            
        print("Renewal successful")
        return JsonResponse({'status': 'success'})
        
    except Exception as e:
        print(f"Renewal error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)

# Helper functions
def check_identity_expiration(client):
    """Check if client identity is expiring soon and create notification"""
    im = IdentityManager(client_id=client.client_id)
    status = im.check_identity_expiration()
    
    if status.startswith("expiring_soon"):
        days = int(status.split('(')[1].split()[0])
        create_notification(
            client_id=client.client_id,
            message=f'Your identity expires in {days} days',
            notification_type='EXPIRATION',
            action_url=f'/renew/{client.client_id}/'
        )

def get_unread_notifications(client_id, limit=5):
    return Notification.objects.filter(
        client__client_id=client_id,
        is_read=False
    ).order_by('-created_at')[:limit]

@login_required
def notification_list(request):
    """View to list all notifications for the authenticated client."""
    client_id = request.user.username  
    notifications = Notification.objects.filter(client__client_id=client_id).order_by('-created_at')
    context = {
        'notifications': notifications,
    }
    return render(request, 'notification_list.html', context)

def get_client_status(client_id):
    im = IdentityManager(client_id=client_id)
    return {
        'status': im.check_identity_expiration(),
        'authorized_peers': im.get_authorized_peers(),
        'last_updated': im.get_last_updated()
    }

def get_recent_logs(client_id, limit=10):
    return ClientLog.objects.filter(
        client__client_id=client_id
    ).order_by('-timestamp')[:limit]

def create_notification(client_id, message, notification_type, action_url=None):
    """Create a new notification for a client"""
    client = Client.objects.get(client_id=client_id)
    Notification.objects.create(
        client=client,
        message=message,
        notification_type=notification_type,
        action_url=action_url
    )


def log_client_activity(client_id, log_type, message, metadata=None):
    """Log client activity to database"""
    client = Client.objects.get(client_id=client_id)
    ClientLog.objects.create(
        client=client,
        log_type=log_type,
        message=message,
        metadata=json.dumps(metadata or {})
    )


@login_required
def check_status(request, client_id):
    im = IdentityManager(client_id=client_id)
    status = im.check_identity_expiration()
    return JsonResponse({'status': status})
