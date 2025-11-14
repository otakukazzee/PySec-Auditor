#!/usr/bin/env python3
import sys, os

# ✅ FIX: pastikan Python mencari folder src lokal dulu
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import firebase_manager

import json, getpass, base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

ADMIN_FILE = os.path.join(os.path.dirname(__file__), 'admin_account_encrypted.json')

def derive_key(password, salt, iterations=200000):
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def decrypt_blob(blob, password):
    try:
        import base64, json
        salt = base64.b64decode(blob['salt'])
        nonce = base64.b64decode(blob['nonce'])
        tag = base64.b64decode(blob['tag'])
        ciphertext = base64.b64decode(blob['ciphertext'])
        iters = int(blob.get('kdf_iter', 200000))
        key = derive_key(password.encode(), salt, iterations=iters)
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode())
    except Exception as e:
        return None

def main():
    print('PySec Admin Info (encrypted) v11.7')
    if not os.path.exists(ADMIN_FILE):
        print('Admin encrypted file not found.'); return
    pwd = getpass.getpass('Enter admin encryption password: ')
    blob = json.load(open(ADMIN_FILE, 'r', encoding='utf-8'))
    dec = decrypt_blob(blob, pwd)
    if not dec:
        print('Failed to decrypt admin file. Wrong password?'); return
    masked = dec.copy()
    masked['username'] = '***REDACTED***'
    print(json.dumps(masked, indent=2))

if __name__ == '__main__':
    main()
