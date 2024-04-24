from Crypto.Cipher import AES, DES
# from Crypto.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import rsa,ec
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from secrets import token_bytes
from Crypto.PublicKey import RSA,ECC

iv = token_bytes(AES.block_size)
key = get_random_bytes(16)

def encryptAES(plainText):

    #CBC Mode: It is a mode of operation where each plaintext block gets XOR-ed 
    # with the previous ciphertext block prior to encryption.
    cipher = AES.new(key, AES.MODE_CBC,iv)
    # cipher = AES.new(key, AES.MODE_EAX)
    plainTextPadded=pad(plainText.encode(), AES.block_size)
    ct_bytes = cipher.encrypt(plainTextPadded)

    return ct_bytes

    

encrypted=encryptAES("19p1689")
print("The encrypted Text (AES) is: ", encrypted)

def decryptAES(cipherText):
    
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode with the given IV
    plainTextPadded = cipher.decrypt(cipherText)  # Decrypt the ciphertext
    plainText = unpad(plainTextPadded, AES.block_size).decode()  # Unpad and decode the plaintext
    return plainText

decrypted=decryptAES(encrypted)
print("The plain text (AES) is: ", decrypted)

    
keyDES = get_random_bytes(8)  # Generate a random 8-byte key for DES
ivDES=get_random_bytes(8)
def encryptDES(plainText):

    cipher = DES.new(keyDES, DES.MODE_CBC, ivDES)  
    paddedPlainText=pad(plainText.encode(),DES.block_size)
    ct_bytes = cipher.encrypt(paddedPlainText) # Encrypt the plaintext
    return ct_bytes  # Return the ciphertext, nonce, and tag
    

def decryptDES( cipherText):
    cipher = DES.new(keyDES, DES.MODE_CBC, ivDES)  # Create DES cipher in CBC mode with the IV
    paddedPlainText = cipher.decrypt(cipherText)# Decrypt the ciphertext
    plainText=unpad(paddedPlainText,DES.block_size).decode()
    return plainText

text="Hello from Aya Ahmed"
cipherText=encryptDES(text)
print("Encrypted text using DES: ",cipherText)
plainText=decryptDES(cipherText)
print("The original plain text (DES) is: ",plainText)

def RSAKey():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
    public_key = private_key.public_key()
    
    return public_key, private_key


def ECCKey():
    # key = ECC.generate(curve='p256')
    private_key = ec.generate_private_key(
    ec.SECP384R1()
)
    public_key = private_key.public_key()
    return private_key,public_key


    
# rsa_private_key, rsa_public_key = RSAKey()
# print("RSA Private key:", rsa_private_key)
# print("RSA Public key:", rsa_public_key)

# ecc_private_key, ecc_public_key = ECCKey()
# print("ECC Private key:", ecc_private_key)
# print("ECC Public key:", ecc_public_key)
    

