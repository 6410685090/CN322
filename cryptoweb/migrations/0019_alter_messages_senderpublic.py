# Generated by Django 5.0.3 on 2024-03-19 15:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0018_messages_senderpublic'),
    ]

    operations = [
        migrations.AlterField(
            model_name='messages',
            name='senderPublic',
            field=models.CharField(default='', max_length=1024),
        ),
    ]
