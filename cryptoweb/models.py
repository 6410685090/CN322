from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class Account(AbstractUser):
    password = models.CharField(max_length=512)
    public_key = models.CharField(max_length=1024)
    private_key = models.CharField(max_length=1024)

    def getPublic_key(self):
        return eval(self.public_key)
    
    def getPrivate_key(self):
        return eval(self.private_key)

class Messages(models.Model):
    sender = models.CharField(max_length=64)
    receiver = models.CharField(max_length=64)
    message = models.CharField(max_length=512)
    signature = models.CharField(max_length=512)
    checkmessage = models.BooleanField(default=True)
    mode = models.CharField(max_length=32,default="None")

class PublicKey(models.Model):
    username = models.CharField(max_length=64)
    key = models.CharField(max_length=1024)

    def getKey(self):
        return eval(self.key)