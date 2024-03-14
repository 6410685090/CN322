from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class Account(AbstractUser):
    password = models.CharField(max_length=512, default=None)
    public_key = models.CharField(max_length=512)
    private_key = models.CharField(max_length=512)

class Messages(models.Model):
    sender = models.CharField(max_length=64)
    receiver = models.CharField(max_length=64)
    message = models.CharField(max_length=512)
    hashmessage = models.CharField(max_length=512, default="")
    checkmessage = models.BooleanField(default=True)