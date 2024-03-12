# Generated by Django 5.0.2 on 2024-03-12 16:27

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0003_delete_customuser'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='private_key',
            field=models.CharField(default=None, max_length=512),
        ),
        migrations.AddField(
            model_name='account',
            name='public_key',
            field=models.CharField(default=None, max_length=512),
        ),
        migrations.AddField(
            model_name='account',
            name='user',
            field=models.OneToOneField(default=None, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='account',
            name='password',
            field=models.CharField(default=None, max_length=512),
        ),
        migrations.AlterField(
            model_name='account',
            name='username',
            field=models.CharField(default=None, max_length=64),
        ),
    ]
