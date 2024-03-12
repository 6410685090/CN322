from django.shortcuts import render
from .models import Account
from django.contrib.auth.models import User
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
        random_public_key = "test" # do a random func -----------------------------
        random_private_key = 'test' # do a random func -----------------------------
        user = User.objects.create_user(username=username,password=password)
        Account.objects.create(username=username,
                               password=password,
                               public_key=random_public_key,
                               private_key=random_private_key,
                               user=user)
        Account.save
        user.save
        

    return render(request , 'cryptoweb/signup.html')

def digital(request):
    return render(request, 'cryptoweb/digital_signature.html',{ 'alluser' : User.objects.all})