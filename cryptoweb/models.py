from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Account(models.Model):
    username = models.CharField(max_length=64, default=None)
    password = models.CharField(max_length=512, default=None)
    public_key = models.CharField(max_length=512, default=None)
    private_key = models.CharField(max_length=512, default=None)