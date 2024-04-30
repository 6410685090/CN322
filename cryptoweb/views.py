from django.shortcuts import render , redirect
from .models import Account , Messages , PublicKey
from .models import Account
from django.contrib.auth import authenticate, login, logout
from . import RSAFunc , customhash
import copy

# Create your views here.


def index(request):
    return render(request , 'cryptoweb/index.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        hashPW = customhash.hash_password(password=password)
        if Account.objects.filter(username=username).exists():
            return render(request , 'cryptoweb/signup.html',{
                'message' : 'Username already exists.'
            })
        public_key , private_key = RSAFunc.RSAGenerateKey()
        PublicKey.objects.create(username=username,key=str(public_key))
        Account.objects.create(username=username,password=hashPW,public_key=public_key,
                               private_key=private_key)
        Account.save
        PublicKey.save
    return render(request , 'cryptoweb/signup.html')

def sendmessage(request):
    if request.user.is_authenticated:
        user = request.user
        messages = Messages.objects.filter(receiver=request.user.username,mode="Digital Signature")
        if request.method == "POST":
            sender = request.user.username       
            receiver = request.POST['receiver']
            message = request.POST['message']
            signature = customhash.hash(message)
            Messages.objects.create(sender=sender,receiver=receiver,
                                    message=message,signature=signature,mode="Digital Signature")

        for m in messages:
            m.checkmessage = (customhash.hash(m.message) == m.signature)

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
            if customhash.verify_password(password, hashPW):
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
        messages = copy.deepcopy(Messages.objects.filter(mode="RSA")) 
        if request.method == "POST":
            sender = request.user.username
            receiver = request.POST['receiver']
            message = request.POST['message']
            receiverKey = PublicKey.objects.get(username=receiver).getKey()
            signature = customhash.hash(message)
            ciphertext = RSAFunc.RSA_encrypt(message=message,key=receiverKey)
            Messages.objects.create(sender=sender,receiver=receiver,
                                    message=ciphertext,signature=signature,mode="RSA")
                   
        key = request.user.getPrivate_key()
        newmessages = []
        for m in messages:
            if request.user.username == m.receiver:
                m.message = RSAFunc.RSA_decrypt(message=m.message,key=key)
                newmessages.append(m)
            else:
                newmessages.append(m)
        
        return render(request, 'cryptoweb/rsa.html',
                    { 'alluser' : Account.objects.all(),
                        'messages' : newmessages,
                    })
    return render(request, 'cryptoweb/signin.html')

def custommessage(request):
    if request.user.is_authenticated:
        realMessagesObject = Messages.objects.all()
        if request.method == "POST":
            sender = request.user.username       
            receiver = request.POST['receiver']
            message = request.POST['message']
            mode = request.POST['mode']

            if mode == "Sender Verify":
                ciphertext = RSAFunc.RSA_encrypt(message=message,key=request.user.getPrivate_key())
            elif mode == "Receiver Verify":
                thisReceiver = PublicKey.objects.get(username=receiver).getKey()
                ciphertext = RSAFunc.RSA_encrypt(message=message,key=thisReceiver)
            elif mode == "Both":
                thisReceiver = PublicKey.objects.get(username=receiver).getKey()
                ciphertext = RSAFunc.RSA_encrypt(message=message,key=thisReceiver)
                ciphertext = RSAFunc.RSA_encrypt(message=ciphertext,key=request.user.getPrivate_key())
            else:
                ciphertext = message

            signature = customhash.hash(message)
            Messages.objects.create(sender=sender,receiver=receiver,
                                    message=ciphertext,signature=signature,mode=mode)

        for m in realMessagesObject:
            m.checkmessage = (customhash.hash(m.message) == m.signature)
  
            
        messages = copy.deepcopy(realMessagesObject) 
        newmessages = []
        for m in messages:
            if m.mode == "None":
                newmessages.append(m)
            elif m.mode == "Sender Verify":
                try: 
                    Senderkey = PublicKey.objects.get(username=m.sender).getKey()
                    m.message = RSAFunc.RSA_decrypt(message=m.message,key=Senderkey)
                except:
                    pass
                newmessages.append(m)
            elif m.mode == "Receiver Verify":
                if m.receiver == request.user.username:
                    Userkey = request.user.getPrivate_key()
                    m.message = RSAFunc.RSA_decrypt(message=m.message,key=Userkey)
                newmessages.append(m)
            elif m.mode == "Both":
                if m.receiver == request.user.username:
                    Userkey = request.user.getPrivate_key()
                    try: 
                        Senderkey = PublicKey.objects.get(username=m.sender).getKey()
                        m.message = RSAFunc.RSA_doubleDecrypt(message=m.message,key1=Senderkey,key2=Userkey)
                    except:
                        pass
                newmessages.append(m)
            else:
                pass

        return render(request, 'cryptoweb/custommessage.html',
                    { 'alluser' : Account.objects.all,
                        'messages' : newmessages,
                    })
    else:
        return render(request, 'cryptoweb/signin.html')


def messageINdb(request):
    messages = Messages.objects.all()
    return render(request, 'cryptoweb/messageINdb.html',
                { 
                    'messages' : messages,
                })