"""Fake Flask-style app for the Claude Security Skills code-secrets-review examples. Every key here is fake."""
import hashlib
import os
import pickle
import subprocess

import requests
import yaml

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://app:Zq9fakePassw0rd@db.example.test:5432/app"
api_token = "f4k3T0k3nQ9vL2mX8pR7sW1yZ6bN3cJ5"
LEGACY_TOKEN = "Hb7fakeLegacyT0kenX2pQ9rS4vW6yZ1"  # secskills:ignore (reviewed: revoked fake)
DEBUG = True


def run(cmd):
    return subprocess.run(cmd, shell=True)


def load(blob, text):
    obj = pickle.loads(blob)
    cfg = yaml.load(text)
    safe = yaml.safe_load(text)
    return obj, cfg, safe


def find_user(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))


def fetch(url):
    return requests.get(url, verify=False)


def checksum(data):
    return hashlib.md5(data).hexdigest()


def calc(expr):
    return eval(expr)


def token_from_env():
    return os.environ.get("API_TOKEN")
