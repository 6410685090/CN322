# Generated by Django 5.0.2 on 2024-03-13 10:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0004_account_private_key_account_public_key_account_user_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='account',
            name='user',
        ),
    ]