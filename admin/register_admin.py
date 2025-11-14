#!/usr/bin/env python3
import sys, os

# ✅ FIX: pastikan Python mencari folder src lokal dulu
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import firebase_manager


import json, uuid, platform, datetime, hashlib, getpass, base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

ADMIN_FILE = os.path.join(os.path.dirname(__file__), 'admin_account_encrypted.json')

def derive_key(password, salt, iterations=200000):
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def encrypt_payload(payload_dict, password):
    salt = get_random_bytes(16)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)
    plaintext = json.dumps(payload_dict).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    blob = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'kdf_iter': 200000
    }
    return blob

def banner():
    print('🛡️ PySec-Auditor Admin Registration (encrypted) v11.7')
    print('-----------------------------------------------------')

def main():
    banner()
    username = input('Admin username: ').strip()
    if not username:
        print('Username required. Aborting.'); return
    pwd = getpass.getpass('Create encryption password (keep it safe): ')
    pwd2 = getpass.getpass('Confirm password: ')
    if pwd != pwd2:
        print('Passwords do not match. Aborting.'); return
    node = platform.node()
    mac = uuid.getnode()
    device_info = f"{node}_{mac}"
    signature = hashlib.sha1(device_info.encode()).hexdigest()[:16]
    payload = {'admin_id': signature[:8].upper(), 'username': username, 'device_signature': signature, 'created_at': datetime.datetime.utcnow().isoformat() + 'Z'}
    blob = encrypt_payload(payload, pwd)
    with open(ADMIN_FILE, 'w', encoding='utf-8') as fh:
        json.dump(blob, fh, indent=2)
    print('Admin encrypted file created at', ADMIN_FILE)
    print('Store your password safely; it is required to use admin tools.')

if __name__ == '__main__':
    main()
