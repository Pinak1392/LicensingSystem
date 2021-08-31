import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def createKey(createTime):
    password_provided = createTime  # This is input in the form of a string
    del createTime
    password = password_provided.encode()  # Convert to type bytes
    del password_provided
    salt = b'\xf10;\xf0\x10\xfa\xf3\xbd*\xed\x88\x19\xd6\x9f\xb3T'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(key, msg):
    message = msg.encode()

    f = Fernet(key)
    return f.encrypt(message)

def decrypt(key, msg):
    f = Fernet(key)
    return f.decrypt(msg)