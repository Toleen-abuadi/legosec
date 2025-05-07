# dashboard/decorators.py
from django.http import JsonResponse
from functools import wraps

def secret_id_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not (request.user.is_authenticated and 
                hasattr(request, 'client_id')):
            return JsonResponse(
                {'error': 'Authentication required'},
                status=401
            )
        return view_func(request, *args, **kwargs)
    return _wrapped_view