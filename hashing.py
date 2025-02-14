import hashlib
import os

# Hashing algorithm using sha256
def hash_password(password): 
    salt = os.urandom(16)  # 16-byte random salt

    # Hash the password with the salt
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()

    # Return the hashed password and the salt, both hex-encoded
    return hashed_password, salt.hex()

def is_password_same(attempted_password, saved_hash, saved_salt): 
    # Decode the hex-encoded salt
    salt = bytes.fromhex(saved_salt)

    # Hash the attempted password with the saved salt
    attempted_hash = hashlib.sha256(salt + attempted_password.encode()).hexdigest()

    # Compare the attempted hash with the saved hash
    return attempted_hash == saved_hash
