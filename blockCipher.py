from Crypto.Cipher import AES, DES
# from Crypto.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import rsa,ec

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from secrets import token_bytes
from Crypto.PublicKey import RSA,ECC



def encryptAES(plainText):
    
    key = get_random_bytes(16)
    iv = token_bytes(AES.block_size)
    #CBC Mode: It is a mode of operation where each plaintext block gets XOR-ed 
    # with the previous ciphertext block prior to encryption.
    cipher = AES.new(key, AES.MODE_CBC,iv)
    # cipher = AES.new(key, AES.MODE_EAX)
    plainTextPadded=pad(plainText.encode(), AES.block_size)
    ct_bytes = cipher.encrypt(plainTextPadded)

    return ct_bytes

    

encrypted=encryptAES("19p1689")
print("The encrypted Text (AES) is: ", encrypted)

def encryptDES(plainText):
    key = get_random_bytes(8)  # Generate a random 8-byte key for DES
    cipher = DES.new(key, DES.MODE_EAX)  # Create DES cipher in EAX mode
    ct, tag = cipher.encrypt_and_digest(plainText.encode())  # Encrypt the plaintext
    return ct, cipher.nonce, tag  # Return the ciphertext, nonce, and tag
    

plaintext = "Hello, DES!"
ct, nonce, tag = encryptDES(plaintext)
print("Ciphertext using DES : ", ct)
print("Nonce:", nonce)
print("Tag:", tag)

def hashingModule():
    
    return
    
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


    
rsa_private_key, rsa_public_key = RSAKey()
print("RSA Private key:", rsa_private_key)
print("RSA Public key:", rsa_public_key)

ecc_private_key, ecc_public_key = ECCKey()
print("ECC Private key:", ecc_private_key)
print("ECC Public key:", ecc_public_key)
    

