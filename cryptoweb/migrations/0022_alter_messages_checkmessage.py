# Generated by Django 5.0.3 on 2024-03-21 16:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0021_publickey_remove_messages_receiverpublic_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='messages',
            name='checkmessage',
            field=models.BooleanField(default=True),
        ),
    ]
