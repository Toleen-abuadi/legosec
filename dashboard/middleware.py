# dashboard/middleware.py
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from .auth import SecretIdAuthBackend 

class SecretIdAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth_backend = SecretIdAuthBackend()

    def __call__(self, request):
        # Skip authentication for login and static files
        if request.path in ('/login/', '/api/login/', '/static/', '/admin/'):
            return self.get_response(request)
            
        if request.user.is_authenticated:
            return self.get_response(request)
            
        # Check for secret ID in headers or session
        client_id = request.headers.get('X-Client-ID')
        encrypted_secret = request.headers.get('X-Encrypted-Secret')

        if not (client_id and encrypted_secret):
            client_id = request.session.get('client_id')
            encrypted_secret = request.session.get('encrypted_secret')

        if client_id and encrypted_secret:
            user = self.auth_backend.authenticate(
                request,
                client_id=client_id,
                encrypted_secret=encrypted_secret
            )
            
            if user:
                request.user = user
                request.session['client_id'] = client_id
                request.session['encrypted_secret'] = encrypted_secret
                return self.get_response(request)
        
        # Redirect to login page for browser requests
        if 'text/html' in request.META.get('HTTP_ACCEPT', ''):
            return HttpResponseRedirect(reverse('login'))
            
        return JsonResponse(
            {'error': 'Authentication required'}, 
            status=401
        )