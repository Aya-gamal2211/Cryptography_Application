import rsa

publicKey , privateKey =rsa.newkeys(1024) #1024 bytes long

with open ("public.pem","rb") as f :
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open ("private.pem","rb") as f :
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

def encryptWithPublicKey():
    
    message="Welcome to security world"
    encrypted_msg = rsa.encrypt(message.encode(),public_key)
    print("The encrypted message is", encrypted_msg)
    # write the encrypted message in a file
    with open('encrypted_msg','wb') as f:
        f.write(encrypted_msg)

## for decryption ##
def decryption():
    encrypted_msg =open ('encrypted_msg','rb').read()
    plaintext = rsa.decrypt(encrypted_msg,private_key) 
    print("plain text is : ",plaintext.decode())

encryptWithPublicKey()
decryption()