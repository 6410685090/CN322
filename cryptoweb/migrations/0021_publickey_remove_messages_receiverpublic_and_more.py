# Generated by Django 5.0.3 on 2024-03-21 10:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptoweb', '0020_messages_receiverpublic'),
    ]

    operations = [
        migrations.CreateModel(
            name='PublicKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=64)),
                ('key', models.CharField(max_length=1024)),
            ],
        ),
        migrations.RemoveField(
            model_name='messages',
            name='receiverPublic',
        ),
        migrations.RemoveField(
            model_name='messages',
            name='senderPublic',
        ),
    ]
