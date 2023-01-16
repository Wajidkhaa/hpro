#coding = utf-8
__author__ = 'Muhammad Hamza (Hop)'
__github__='https://github.com/hop09'
try:
    import os
    import sys
    import time
    import io
    import struct
    import base64
    import random
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    os.system('pip install pycryptodome requests')

class PasswordEnc:
    def __init__(self,password,app):
        self.userpassword = password
        self.apk = app
        self.public = open('.pubkey.txt','r').read()
        self.key_id = int(open('.key.txt','r').read())
        self.enc()
        
        
    def enc(self):
        password = self.userpassword
        rand_key = get_random_bytes(32)
        iv = get_random_bytes(12)
        pubkey_bytes = self.public
        pubkey = RSA.import_key(pubkey_bytes)
        cipher_rsa = PKCS1_v1_5.new(pubkey)
        encrypted_rand_key = cipher_rsa.encrypt(rand_key)
        cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
        current_time = int(time.time())
        cipher_aes.update(str(current_time).encode("utf-8"))
        encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))
        buf = io.BytesIO()
        buf.write(bytes([1, int(self.key_id)]))
        buf.write(iv)
        buf.write(struct.pack("<h", len(encrypted_rand_key)))
        buf.write(encrypted_rand_key)
        buf.write(auth_tag)
        buf.write(encrypted_passwd)
        encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
        enc_pas = f'#PWD_{self.apk}:2:{current_time}:{encoded}'
        return enc_pas
