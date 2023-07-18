import base64
import hashlib
import re
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AesHelper: 

    def encrypt(self, plain_text, key, iv):
        if plain_text is None or len(plain_text) == 0:
            raise NameError("No value given to encrypt")
        plain_text = plain_text + '\0' * (BS - len(plain_text) % BS)
        plain_text = plain_text.encode('utf-8')
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plain_text)).decode('utf-8')

    def decrypt(self, encrypted, key, iv):
        if encrypted is None or len(encrypted) == 0:
            raise NameError("No value given to decrypt")
        encrypted = base64.b64decode(encrypted)
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return re.sub(b'\x00*$', b'', cipher.decrypt( encrypted[16:])).decode('utf-8')
