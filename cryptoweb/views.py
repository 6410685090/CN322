from django.shortcuts import render , redirect
from .models import Account , Messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
# Create your views here.

def index(request):
    return render(request , 'cryptoweb/index.html')

def signup(request):
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
                               private_key=random_private_key,)
        Account.save
        user.save
    return render(request , 'cryptoweb/signup.html')

def sendmessage(request):
    if request.user.is_authenticated:
        messages = Messages.objects.filter(receiver=request.user.username)
        if request.method == "POST":
            sender = request.user.username
            receiver = request.POST['receiver']
            message = request.POST['message']
            # hashmessage = 
            Messages.objects.create(sender=sender,receiver=receiver,message=message)

        # check message method

        return render(request, 'cryptoweb/digital_signature.html',
                    { 'alluser' : User.objects.all,
                        'messages' : messages,
                    })
    else:
        return render(request, 'cryptoweb/signin.html')
    

def signin(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)  
            return redirect('home')
        
        else:
            return render(request, 'cryptoweb/signin.html', {
                'message': 'Invalid credentials.'
            })
    return render(request, 'cryptoweb/signin.html')

def logout_view(request):
    logout(request)
    return render(request, 'cryptoweb/index.html', {
        'message': 'Logged out'
    })

def sendmessagersa(request):
    if request.user.is_authenticated:
        messages = Messages.objects.all
        if request.method == "POST":
            sender = request.user.username
            receiver = request.POST['receiver']
            message = request.POST['message']
            # RSA encrypt method 
            Messages.objects.create(sender=sender,receiver=receiver,message=message)

        # RSA decrypt method

        return render(request, 'cryptoweb/rsa.html',
                    { 'alluser' : User.objects.all,
                        'messages' : messages,
                    })
    return render(request, 'cryptoweb/rsa.html')