# Generated by Django 5.0.2 on 2024-03-13 10:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0007_rename_message_messages'),
    ]

    operations = [
        migrations.AlterField(
            model_name='messages',
            name='receiver',
            field=models.CharField(max_length=64),
        ),
        migrations.AlterField(
            model_name='messages',
            name='sender',
            field=models.CharField(max_length=64),
        ),
    ]
