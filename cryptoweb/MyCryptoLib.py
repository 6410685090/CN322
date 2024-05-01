from .customhash import hashSha256, hashMd5, hashSha1 , hash_whirlpool,\
    hash_blake2b, hash_blake2s, hash_ripemd160 , generate_random_hex

from .RSAFunc import RSA_encrypt, RSA_decrypt, RSAGenerateKey , RSASignature, \
    RSAVerify, RSA_doubleDecrypt , RSA_doubleDecrypt
 
def hash(message, mode="sha256"):
    if mode == 'sha1':
        return hashSha1(message)
    elif mode == 'md5':
        return hashMd5(message)
    elif mode == 'sha256':
        return hashSha256(message)
    elif mode == 'whirlpool':
        return hash_whirlpool(message)
    elif mode == 'blake2b':
        return hash_blake2b(message)
    elif mode == 'blake2s':
        return hash_blake2s(message)
    elif mode == 'ripemd160':
        return hash_ripemd160(message)
    else:
        return KeyError("Invalid mode")

def hash_password(password, mode="sha256", salt=None):
    if mode == 'sha1':
        hashPassword = hashSha1(password)
    elif mode == 'md5':
        hashPassword = hashMd5(password)
    elif mode == 'sha256':
        hashPassword = hashSha256(password)
    elif mode == 'whirlpool':
        hashPassword = hash_whirlpool(password)
    elif mode == 'blake2b':
        hashPassword = hash_blake2b(password)
    elif mode == 'blake2s':
        hashPassword = hash_blake2s(password)
    elif mode == 'ripemd160':
        hashPassword = hash_ripemd160(password)
    else:
        return KeyError("Invalid mode")
    
    if salt is None:
        salt = generate_random_hex(16)
    return str(salt) + hashPassword
    
def verify_password(password, hashed_password , mode="sha256"):
    salt = hashed_password[:16]

    new_hashed_password = hash_password(password=password,salt=salt,mode=mode)
    if hashed_password == new_hashed_password:
        return True
    else:
        return False

def Generate_Key():
    return RSAGenerateKey()

def encrypt(message, key):
    return RSA_encrypt(message, key)

def decrypt(message, key):
    return RSA_decrypt(message, key)

def sign(message, private_key):
    return RSASignature(message, private_key)

def verify(message, signature, public_key):
    return RSAVerify(message, signature, public_key)

def doubleDecrypt(message, key1, key2):
    return RSA_doubleDecrypt(message, key1, key2)

def doubleEncrypt(message, key1, key2):
    return RSA_encrypt(RSA_encrypt(message, key1), key2)
