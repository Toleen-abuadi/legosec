# dashboard/signals.py
from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import ClientLog, Client

@receiver(pre_save, sender=Client)
def log_authentication_attempt(sender, instance, **kwargs):
    if instance.pk:  # Only for existing clients
        original = Client.objects.get(pk=instance.pk)
        if original.last_seen != instance.last_seen:
            ClientLog.objects.create(
                client=instance,
                log_type='AUTH',
                message=f"Client authenticated from {instance.last_ip}",
                metadata={
                    'ip': instance.last_ip,
                    'user_agent': instance.last_user_agent
                }
            )