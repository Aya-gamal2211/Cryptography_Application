import rsa
############# verify the signature at the receiver side ###############
input("enter receiver name :")
with open ("shimo_public.pem") as f :
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open ("aya_private.pem") as f :
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# get the value of the public key 
message=open ('encrypted_msg','rb').read()
signature=open ("Aly_signature",'rb').read()

try:
    rsa.verify(message,signature,public_key)
    print("signature is correct , message sent correctly")
    encrypted_msg =open ('encrypted_msg','rb').read()
    ## check the original plain text
    plaintext = rsa.decrypt(encrypted_msg,private_key) 
    print("plain text is : ",plaintext)
except:
    print("your signature is incorrect, check it again")


