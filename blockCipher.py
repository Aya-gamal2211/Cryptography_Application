from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from secrets import token_bytes



def encrypt(plainText):
    
    key = get_random_bytes(16)
    iv = token_bytes(AES.block_size)
    #CBC Mode: It is a mode of operation where each plaintext block gets XOR-ed 
    # with the previous ciphertext block prior to encryption.
    cipher = AES.new(key, AES.MODE_CBC,iv)
    plainTextPadded=pad(plainText.encode(), AES.block_size)
    ct_bytes = cipher.encrypt(plainTextPadded)

    return ct_bytes

    

encrypted=encrypt("19p1689")
print("The encrypted Text is: ", encrypted)

    

