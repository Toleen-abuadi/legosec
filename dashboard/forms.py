from django import forms
from .models import Client, Authorization, SystemParameter

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ['name', 'encrypted_secret', 'public_key', 'ip_address', 'is_active']
        widgets = {
            'encrypted_secret': forms.Textarea(attrs={'rows': 3}),
            'public_key': forms.Textarea(attrs={'rows': 5}),
        }

class AuthorizationForm(forms.ModelForm):
    class Meta:
        model = Authorization
        fields = ['client', 'authorized_client', 'is_active']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['client'].queryset = Client.objects.filter(is_active=True)
        self.fields['authorized_client'].queryset = Client.objects.filter(is_active=True)

class SystemParameterForm(forms.ModelForm):
    class Meta:
        model = SystemParameter
        fields = ['name', 'param_type', 'value', 'description']