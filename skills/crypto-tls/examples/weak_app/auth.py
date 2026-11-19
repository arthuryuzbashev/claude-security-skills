"""Fictional login service with the classic crypto mistakes. Fake values only."""
import hashlib
import random
import ssl

import jwt
import requests
from Crypto.Cipher import AES, DES

SECRET_KEY = "fAkE0nlyK3yForTestsDoNotUse1234"
IV = b"\x00" * 16
iv = b"0000000000000000"


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def make_reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))  # reset token


def encrypt(data):
    cipher = AES.new(SECRET_KEY.encode()[:16], AES.MODE_ECB)
    return cipher.encrypt(data)


def legacy_encrypt(data):
    return DES.new(b"8bytekey", DES.MODE_CBC, iv=iv[:8]).encrypt(data)


def fetch_profile(url):
    return requests.get(url, verify=False, timeout=5)


def read_token(token):
    return jwt.decode(token, options={"verify_signature": False})


def accept_any_alg(token, key):
    return jwt.decode(token, key, algorithms=["HS256", "none"])


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
