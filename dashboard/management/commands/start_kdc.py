from django.core.management.base import BaseCommand
from legosec.kdc_server import KDCServer

class Command(BaseCommand):
    help = 'Start the KDC server'

    def handle(self, *args, **kwargs):
        server = KDCServer()
        server.start()
