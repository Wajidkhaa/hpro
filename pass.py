#coding = utf-8
__author__ = 'Muhammad Hamza (Hop)'
__github__='https://github.com/hop09'
try:
    import os
    import sys
    import time
    import io
    import struct
    import uuid
    import base64
    import random
    import requests
    import subprocess
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    os.system('pip install pycrytodome requests')

class PasswordEnc:
    def __init__(self,access_token,password,app):
        self.token = access_token
        self.userpassword = password
        self.apk = app
        self.model = subprocess.check_output('getprop ro.product.model',shell=True).decode('utf-8').replace('\n','')
        self.my_phone = subprocess.check_output('getprop ro.product.manufacturer',shell=True).decode('utf-8').replace('\n','')
        self.ad_version = subprocess.check_output('getprop ro.build.version.release',shell=True).decode('utf-8').replace('\n','')
        self.build = subprocess.check_output('getprop ro.build.id',shell=True).decode('utf-8').replace('\n','')
        try:
            self.public = open('.pubkey.txt','r').read()
            self.key_id = int(open('.key.txt','r').read())
        except:
            self.store_keys(self.token,self.apk)
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
        
        
    @property    
    def store_keys(self):
        if '256002347743983' in self.token:
            self.callerClass = 'AuthOperations'
            self.packageName = 'com.facebook.orca'
            self.fban = 'Orca-Android'
        else:
            self.callerClass = 'Fb4aAuthHandler'
            self.packageName = 'com.facebook.katana'
            self.fban = 'FB4A'
        self.data = {
            'device_id':str(uuid.uuid4()),
            'version':'2',
          #  'flow':'CONTROLLED_INITIALIZATION',
            'locale':'en_US',
            'client_country_code':self.country(),
            'method':'GET',
            'fb_api_request_friendly_name':'pwdKeyFetch',
            'fb_api_caller_class':self.callerClass,
            'access_token':self.token
        }
        self.headers = {
            'Host':'b-graph.facebook.com',
            'Authorization':'OAuth null',
            'X-Fb-Connection-Quality':'EXCELLENT',
            'X-Fb-Sim-Hni':str(random.randint(11111,99999)),
            'X-Fb-Net-Hni':str(random.randint(11111,99999)),
            'User-Agent':f'[FBAN/{self.fban};FBAV/378.0.0.18.112;FBBV/387362546;'+'FBDM/{density=2.0,width=720,height=1432}'+f';FBLC/en_US;FBRV/0;FBCR/Telenor;FBMF/{self.my_phone};FBPN/{self.packageName};FBDV/{self.model};FBSV/{self.ad_version};FBOP/1;FBCA/armeabi-v7a-armeabi;]',
            'Content_Type':'application/x-www-form-urlencoded',
            'X-Fb-Connection-Type':'MOBILE.LTE',
            'X-Fb-Device-Group':str(random.randint(111,999)),
            'X-Tigon-Is-Retry':'False',
            'X-Fb-Friendly-Name':'pwdKeyFetch',
            'X-Fb-Request-Analytics-Tags':'Unknown',
            'Accept-Encoding':'gzip, deflate',
            'X-Fb-Http-Engine':'Liger'
        }
        try:
            self.get_key = requests.post('https://b-graph.facebook.com//pwd_key_fetch',data=self.data,headers=self.headers).json()
       #     print(self.get_key)
            self.pubkey = open('.pubkey.txt','w').write(self.get_key['public_key'])
            self.keyId = open('.key.txt','w').write(str(self.get_key['key_id']))
        except requests.exceptions.ConnectionError:
            print(' No internet connection !')
        print('\n Public key & key_id has been saved, import module again !')
        os.sys.exit()

    def country(self):
        ip = requests.get('http://ip-api.com/json').json()
        return ip['countryCode']