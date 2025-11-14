#!/usr/bin/env python3
import sys, os

# ✅ FIX: pastikan Python mencari folder src lokal dulu
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import firebase_manager


import argparse, json, uuid, platform, hashlib, getpass, base64, secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from src import firebase_manager

ADMIN_FILE = os.path.join(os.path.dirname(__file__), 'admin_account_encrypted.json')

def derive_key(password, salt, iterations=200000):
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def decrypt_blob(blob, password):
    try:
        salt = base64.b64decode(blob['salt'])
        nonce = base64.b64decode(blob['nonce'])
        tag = base64.b64decode(blob['tag'])
        ciphertext = base64.b64decode(blob['ciphertext'])
        iters = int(blob.get('kdf_iter', 200000))
        key = derive_key(password.encode(), salt, iterations=iters)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode())
    except Exception as e:
        return None

def banner():
    print('🛡️ PySec Admin Key Tool (encrypted) v11.7')
    print('------------------------------------------')

def verify_admin(decrypted):
    node = platform.node()
    mac = uuid.getnode()
    device_info = f"{node}_{mac}"
    signature = hashlib.sha1(device_info.encode()).hexdigest()[:16]
    saved_sig = decrypted.get('device_signature')

    # Termux tolerance: allow match by first 8 chars or if same hostname
    if signature == saved_sig:
        return True
    if saved_sig and saved_sig[:8] == signature[:8]:
        return True
    if node in decrypted.get('username', ''):
        return True
    return False

def generate_key(prefix='PREM', bits=8):
    return f"{prefix}-" + secrets.token_hex(bits).upper()[:bits*2]

def list_keys():
    ok, data = firebase_manager.list_keys()
    if not ok:
        print('Failed to list keys:', data); return
    print('Keys in Firebase:')
    for k,v in (data.items() if isinstance(data, dict) else []):
        plan = v.get('plan'); active = v.get('is_active', True)
        created = v.get('created_at'); 
        print(f" - {k}: plan={plan}, active={active}, created_at={created}")

def revoke_key(key):
    ok, resp = firebase_manager.revoke_key(key)
    if ok:
        print('Key revoked:', key)
    else:
        print('Failed to revoke key:', resp)

def main():
    banner()
    p = argparse.ArgumentParser(description='Admin key tool (encrypted admin file).')
    p.add_argument('--plan', choices=['15day','30day','unlimited'], default='30day')
    p.add_argument('--prefix', default='PREM')
    p.add_argument('--list', action='store_true', help='List keys in Firebase')
    p.add_argument('--revoke', help='Revoke given key')
    args = p.parse_args()
    if not os.path.exists(ADMIN_FILE):
        print('Admin encrypted file not found. Run register_admin_pycrypto.py first.'); return
    pwd = getpass.getpass('Enter admin encryption password: ')
    blob = json.load(open(ADMIN_FILE, 'r', encoding='utf-8'))
    dec = decrypt_blob(blob, pwd)
    if not dec:
        print('Failed to decrypt admin file. Wrong password?'); return
    if not verify_admin(dec):
        print('Unauthorized device. This tool can only be used on the registered admin device.'); return
    print('Welcome,', dec.get('username'), '- Admin ID:', dec.get('admin_id'))
    if args.list:
        list_keys(); return
    if args.revoke:
        revoke_key(args.revoke); return
    # generate key
    key = generate_key(prefix=args.prefix)
    ok, resp = firebase_manager.add_key(key, plan=args.plan)
    if ok:
        print('Generated key:', key, 'plan=', args.plan)
    else:
        print('Failed to upload key:', resp)

if __name__ == '__main__':
    main()
