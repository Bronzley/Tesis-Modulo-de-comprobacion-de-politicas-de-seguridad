# Generated by Django 5.1 on 2024-11-05 00:24

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ComputerProperties',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('computer_id', models.IntegerField(unique=True)),
                ('name', models.CharField(max_length=255)),
                ('lab', models.CharField(max_length=255)),
                ('ip_address', models.GenericIPAddressField()),
                ('operating_system', models.CharField(max_length=255)),
                ('disk', models.CharField(max_length=255)),
                ('motherboard', models.CharField(max_length=255)),
                ('ram', models.CharField(max_length=255)),
                ('last_update', models.DateTimeField()),
                ('antivirus', models.CharField(max_length=255)),
                ('antivirus_enabled', models.BooleanField(default=False)),
                ('antivirus_updated', models.BooleanField(default=False)),
                ('antivirus_update_frequency', models.CharField(default='N/A', max_length=255)),
                ('antivirus_scan_frequency', models.CharField(default='N/A', max_length=255)),
                ('user', models.CharField(default='N/A', max_length=255)),
                ('password', models.CharField(default='N/A', max_length=255)),
                ('firewall', models.CharField(max_length=255)),
                ('domain', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
            ],
        ),
    ]
