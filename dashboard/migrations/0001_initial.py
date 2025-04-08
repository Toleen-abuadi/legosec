# Generated by Django 5.2 on 2025-04-02 20:37

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('identifier', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, verbose_name='Client ID')),
                ('name', models.CharField(blank=True, help_text='Optional human-readable name', max_length=100, null=True)),
                ('encrypted_secret', models.TextField(help_text="Secret ID encrypted with KDC's public key", verbose_name='Encrypted Secret ID')),
                ('public_key', models.TextField(blank=True, help_text="Client's public key if available", null=True, verbose_name='Client Public Key')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True, verbose_name='Last Known IP')),
                ('is_active', models.BooleanField(default=True, verbose_name='Active Status')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Registration Date')),
                ('expires_at', models.DateTimeField(verbose_name='Expiration Date')),
                ('last_accessed', models.DateTimeField(auto_now=True, verbose_name='Last Access')),
            ],
            options={
                'verbose_name': 'Registered Client',
                'verbose_name_plural': 'Registered Clients',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='SystemParameter',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True, verbose_name='Parameter Name')),
                ('param_type', models.CharField(choices=[('INT', 'Integer'), ('STR', 'String'), ('BOOL', 'Boolean'), ('JSON', 'JSON')], max_length=4, verbose_name='Parameter Type')),
                ('value', models.TextField(verbose_name='Parameter Value')),
                ('description', models.TextField(blank=True, verbose_name='Description')),
                ('last_modified', models.DateTimeField(auto_now=True, verbose_name='Last Modified')),
            ],
            options={
                'verbose_name': 'System Parameter',
                'verbose_name_plural': 'System Parameters',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='SessionKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_id', models.UUIDField(default=uuid.uuid4, editable=False, verbose_name='Key ID')),
                ('session_key', models.TextField(verbose_name='Encrypted Session Key')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Creation Time')),
                ('expires_at', models.DateTimeField(verbose_name='Expiration Time')),
                ('is_active', models.BooleanField(default=True, verbose_name='Active')),
                ('initiator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='initiated_sessions', to='dashboard.client', verbose_name='Initiator Client')),
                ('responder', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='responded_sessions', to='dashboard.client', verbose_name='Responder Client')),
            ],
            options={
                'verbose_name': 'Session Key',
                'verbose_name_plural': 'Session Keys',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ConnectionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_id', models.UUIDField(default=uuid.uuid4, editable=False, verbose_name='Log ID')),
                ('connection_type', models.CharField(choices=[('KDC', 'KDC Authentication'), ('P2P', 'Peer-to-Peer'), ('REG', 'Registration'), ('AUTH', 'Authorization Check')], max_length=4, verbose_name='Connection Type')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Timestamp')),
                ('status', models.CharField(choices=[('SUCCESS', 'Success'), ('FAILED', 'Failed'), ('PENDING', 'Pending'), ('TIMEOUT', 'Timeout')], max_length=7, verbose_name='Status')),
                ('details', models.TextField(blank=True, verbose_name='Additional Details')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True, verbose_name='IP Address')),
                ('duration', models.DurationField(blank=True, null=True, verbose_name='Connection Duration')),
                ('initiator', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='initiated_connections', to='dashboard.client', verbose_name='Initiator')),
                ('target', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='received_connections', to='dashboard.client', verbose_name='Target')),
                ('session_key_ref', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='dashboard.sessionkey', verbose_name='Associated Session Key')),
            ],
            options={
                'verbose_name': 'Connection Log',
                'verbose_name_plural': 'Connection Logs',
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='Authorization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Authorization Date')),
                ('is_active', models.BooleanField(default=True, verbose_name='Active')),
                ('authorized_client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='incoming_authorizations', to='dashboard.client', verbose_name='Authorized Client')),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='outgoing_authorizations', to='dashboard.client', verbose_name='Source Client')),
            ],
            options={
                'verbose_name': 'Client Authorization',
                'verbose_name_plural': 'Client Authorizations',
                'ordering': ['client', 'authorized_client'],
                'unique_together': {('client', 'authorized_client')},
            },
        ),
        migrations.AddIndex(
            model_name='sessionkey',
            index=models.Index(fields=['initiator', 'responder'], name='dashboard_s_initiat_c601f0_idx'),
        ),
        migrations.AddIndex(
            model_name='sessionkey',
            index=models.Index(fields=['expires_at'], name='dashboard_s_expires_7b034e_idx'),
        ),
        migrations.AddIndex(
            model_name='connectionlog',
            index=models.Index(fields=['connection_type'], name='dashboard_c_connect_f11bc6_idx'),
        ),
        migrations.AddIndex(
            model_name='connectionlog',
            index=models.Index(fields=['status'], name='dashboard_c_status_24884a_idx'),
        ),
        migrations.AddIndex(
            model_name='connectionlog',
            index=models.Index(fields=['timestamp'], name='dashboard_c_timesta_c8e799_idx'),
        ),
    ]
