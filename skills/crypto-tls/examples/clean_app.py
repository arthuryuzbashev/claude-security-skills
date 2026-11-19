"""Fictional service doing crypto the boring, correct way."""
import os
import secrets

import requests
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ph = PasswordHasher()  # argon2id defaults


def hash_password(password):
    return ph.hash(password)


def make_reset_token():
    return secrets.token_urlsafe(32)


def encrypt(key, data, aad=b""):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def fetch_profile(url):
    return requests.get(url, timeout=5, verify="/etc/ssl/certs/internal-ca.pem")


SIGNING_KEY = os.environ["SIGNING_KEY"]


def derive_key(password, salt):
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)


def wrap_key(public_key, key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
