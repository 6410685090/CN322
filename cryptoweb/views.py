from django.shortcuts import render , redirect
from .models import Account , Messages
from .models import Account
from django.contrib.auth import authenticate, login, logout
from . import RSAFunc
import bcrypt

# Create your views here.


def index(request):
    return render(request , 'cryptoweb/index.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        hashPW = hashPassword(password)
        if Account.objects.filter(username=username).exists():
            return render(request , 'cryptoweb/signup.html',{
                'message' : 'Username already exists.'
            })
        public_key , private_key , n = RSAFunc.RSAGenerateKey()
        
        Account.objects.create(username=username,password=hashPW,public_key=public_key,
                               private_key=private_key,n=n)
        Account.save
    return render(request , 'cryptoweb/signup.html')

def sendmessage(request):
    if request.user.is_authenticated:
        user = request.user
        messages = Messages.objects.filter(receiver=request.user.username)
        if request.method == "POST":
            sender = request.user.username
            thissender = Account.objects.get(username=sender).getPublic_key()            
            receiver = request.POST['receiver']
            thisReceiver = Account.objects.get(username=receiver).getPublic_key()
            message = request.POST['message']
            ciphertext = RSAFunc.RSASignature(message=message,private_key=user.getPrivate_key())
            Messages.objects.create(sender=sender,receiver=receiver,
                                    message=message,signature=ciphertext,
                                    senderPublic=str(thissender),
                                    receiverPublic=str(thisReceiver),
                                    checkmessage=True)

        for m in messages:
            thisSender = Account.objects.get(username=m.sender)
            m.checkmessage = RSAFunc.RSAVerify(message=m.message ,signature=m.signature,public_key=thisSender.getPublic_key() )

        return render(request, 'cryptoweb/digital_signature.html',
                    { 'alluser' : Account.objects.all,
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
        try:
            user = Account.objects.get(username=username)
            hashPW = user.password
            if verifyPassword(password, hashPW):
                if user is not None:
                    login(request, user)  
                    return redirect('home')
                
                else:
                    return render(request, 'cryptoweb/signin.html', {
                        'message': 'Invalid credentials.'
                    })
            else:
                return render(request, 'cryptoweb/signin.html', {
                    'message': 'Invalid credentials.'
                })
        except:
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)  
                return redirect('home')
    return render(request, 'cryptoweb/signin.html')

def logout_view(request):
    logout(request)
    return render(request, 'cryptoweb/index.html', {
        'message': 'Logged out'
    })

def sendmessagersa(request):
    if request.user.is_authenticated:
        messages = Messages.objects.all()
        if request.method == "POST":
            sender = request.user.username
            receiver = request.POST['receiver']
            message = request.POST['message']
            thissender = Account.objects.get(username=sender).getPublic_key()
            thisReceiver = Account.objects.get(username=receiver).getPublic_key()
            #hash text
            #ciphertext = 
            Messages.objects.create(sender=sender,receiver=receiver,
                                    message=message,signature="None",
                                    senderPublic=str(thissender),
                                    receiverPublic=str(thisReceiver),
                                    checkmessage=True)
        newmessages = []
        for m in messages:
            if request.user.getPrivate_key() == eval(m.receiverPublic):
                #un hash text
                #message = 
                #message.save()
                newmessages.append(m)
            else:
                newmessages.append(m)
        return render(request, 'cryptoweb/rsa.html',
                    { 'alluser' : Account.objects.all(),
                        'messages' : newmessages,
                    })
    return render(request, 'cryptoweb/signin.html')

def hashPassword(password):#
    hashPass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashPass.decode('utf-8')

def verifyPassword(password, hashPW):
    password = str(password)
    return bcrypt.checkpw(password.encode('utf-8'), hashPW.encode('utf-8'))
    
