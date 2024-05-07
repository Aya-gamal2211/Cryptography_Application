import rsa
############# verify the user at decrypting the message ###############

username=input("Enter your username : ")
with open (f"{username}_public.pem") as f :
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open (f"{username}_private.pem") as f :
            
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# get the value of the public key 
message=open ('message','rb').read()
signature=open ('signature_file','rb').read()

try:
    encrypted_msg =open ('encrypted_msg1','rb').read()
    plaintext = rsa.decrypt(encrypted_msg,private_key) 
    print("plain text is : ",plaintext)
    rsa.verify(encrypted_msg,signature,public_key)
    print("signature is correct , success sending message")

except:
    print("your signature is incorrect, check it again")


