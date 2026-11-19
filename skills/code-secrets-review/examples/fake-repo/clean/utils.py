"""Clean file: no secrets, no risky calls."""
import hashlib
import os
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def list_dir(path):
    return subprocess.run(["ls", path], check=True, capture_output=True)


def api_key():
    return os.environ["API_KEY"]
