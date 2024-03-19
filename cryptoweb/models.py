from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class Account(AbstractUser):
    password = models.CharField(max_length=512)
    public_key = models.CharField(max_length=512)
    private_key = models.CharField(max_length=512)
    n = models.CharField(max_length=512)

    def getPublic_key(self):
        return (self.public_key,self.n)
    
    def getPrivate_key(self):
        return (self.private_key,self.n)

class Messages(models.Model):
    sender = models.CharField(max_length=64)
    senderPublic = models.CharField(max_length=1024 ,default="") #512 is not enougt for (e,n)
    receiverPublic =  models.CharField(max_length=1024 ,default="")
    receiver = models.CharField(max_length=64)
    message = models.CharField(max_length=512)
    signature = models.CharField(max_length=512)
    checkmessage = models.BooleanField()