from django.shortcuts import render
from .models import Account
# Create your views here.

def index(request):
    return render(request , 'cryptoweb/index.html')

def passenc(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if Account.objects.filter(username=username).exists():
            return render(request , 'cryptoweb/signup.html',{
                'message' : 'Username already exists.'
            })
        Account.objects.create(username=username,password=password)
        Account.save
    return render(request , 'cryptoweb/signup.html')