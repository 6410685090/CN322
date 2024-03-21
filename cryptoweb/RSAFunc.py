from Crypto.Util.number import getStrongPrime
import random

def RSAGenerateKey():
    p = getStrongPrime(512)
    q = getStrongPrime(512)
    n = p * q
    phi = (p-1)*(q-1)
    e = select_e(phi)
    d = pow(e, -1, phi)
    public_key = e
    private_key = d
    return public_key, private_key , n

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def select_e(phi):
    while True:
        e = random.randint(2, phi - 1)
        if gcd(e, phi) == 1:
            return e

def RSASignature(message, private_key):
    d, n = private_key
    d = int(d)
    n = int(n)
    message = int.from_bytes(message.encode(), byteorder='big')
    signature = pow(message, d, n)
    return signature

def RSAVerify(message, signature, public_key):
    e, n = public_key
    e = int(e)
    n = int(n)
    signature = int(signature)
    message = int.from_bytes(message.encode(), byteorder='big')
    return message == pow(signature, e, n)

def RSA_encrypt(message, key):
    e, n = key
    e = int(e)
    n = int(n)
    message = int.from_bytes(message.encode(), byteorder='big')
    return pow(message, e, n)

def RSA_decrypt(message, key):
    d, n = key
    d = int(d)
    n = int(n)
    message = int(message)
    decrypted_message = pow(message, d, n)
    return decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big').decode()
