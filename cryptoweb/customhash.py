import hashlib , secrets 

def hash(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode())
    hash_message = sha256.hexdigest()
    return hash_message

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

