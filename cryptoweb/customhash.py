import hashlib , secrets 

def hashSha256(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode())
    hash_message = sha256.hexdigest()
    return hash_message

def hashMd5(message):
    md5 = hashlib.md5()
    md5.update(message.encode())
    hash_message = md5.hexdigest()
    return hash_message

def hashSha1(message):
    sha1 = hashlib.sha1()
    sha1.update(message.encode())
    hash_message = sha1.hexdigest()
    return hash_message

def hash_whirlpool(message):
    whirlpool = hashlib.new('whirlpool')
    whirlpool.update(message.encode())
    return whirlpool.hexdigest()

def hash_blake2b(message):
    blake2b = hashlib.blake2b()
    blake2b.update(message.encode())
    return blake2b.hexdigest()

def hash_blake2s(message):
    blake2s = hashlib.blake2s()
    blake2s.update(message.encode())
    return blake2s.hexdigest()

def hash_ripemd160(message):
    ripemd = hashlib.new('ripemd160')
    ripemd.update(message.encode())
    return ripemd.hexdigest()

def hash_password(password, salt=None):
    if salt is None:
        salt = generate_random_hex(16)
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    hashpassword = sha256.hexdigest()

    return str(salt) + hashpassword

def verify_password(password, hashed_password):
    salt = hashed_password[:16]

    new_hashed_password = hash_password(password=password,salt=salt)
    if hashed_password == new_hashed_password:
        return True
    else:
        return False

def generate_random_hex(length):
    num_bytes = length // 2  
    random_bytes = secrets.token_bytes(num_bytes)
    random_hex = random_bytes.hex()
    return random_hex

