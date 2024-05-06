import rsa
from Authentication.authenticate import verify,register_new
# check that the user is logged in
username = input("Please enter your username :")
password = input("Enter your password: ")
isUser = verify(username,password,"auth.txt")
if(isUser==True):
    #  get the value of the private key generated
    with open ("private.pem","rb") as f :
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    ############# sign the message with the owners of the private key ########
    message=open ('message','rb').read()
    hash_value =rsa.compute_hash(message,"SHA-256")
    signature =rsa.sign(message,private_key,"SHA-256")
    signature_file=open('signature_file','wb')
    signature_file.write(signature)
    print(signature)
else :
    print("wrong user name or password ")