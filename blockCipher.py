from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(plainText):
    
    key = get_random_bytes(16)
    #CBC Mode: It is a mode of operation where each plaintext block gets XOR-ed 
    # with the previous ciphertext block prior to encryption.
    cipher = AES.new(key, AES.MODE_CBC)
    
    

