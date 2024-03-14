from django.db import models
# Create your models here.

class Account(models.Model):
    username = models.CharField(max_length=64, default=None)
    password = models.CharField(max_length=512, default=None)
    public_key = models.CharField(max_length=512, default=None)
    private_key = models.CharField(max_length=512, default=None)

class Messages(models.Model):
    sender = models.CharField(max_length=64)
    receiver = models.CharField(max_length=64)
    message = models.CharField(max_length=512)
    hashmessage = models.CharField(max_length=512, default="")
    checkmessage = models.BooleanField(default=True)