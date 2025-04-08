from django.db import migrations

def create_initial_parameters(apps, schema_editor):
    SystemParameter = apps.get_model('dashboard', 'SystemParameter')
    
    parameters = [
        {
            'name': 'SESSION_KEY_EXPIRY_HOURS',
            'param_type': 'INT',
            'value': '24',
            'description': 'Session key validity duration in hours'
        },
        {
            'name': 'CLIENT_REGISTRATION_EXPIRY_DAYS',
            'param_type': 'INT',
            'value': '30',
            'description': 'Client registration validity duration in days'
        },
        {
            'name': 'ALLOW_AUTO_RENEWAL',
            'param_type': 'BOOL',
            'value': 'True',
            'description': 'Whether to allow automatic renewal of expired clients'
        },
    ]
    
    for param in parameters:
        SystemParameter.objects.create(**param)

class Migration(migrations.Migration):
    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_initial_parameters),
    ]