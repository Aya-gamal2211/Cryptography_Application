import hashlib
import rsa
import os

def SignIn(username, password, filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                rows = line.strip().split(',')
                if rows[0] == username.strip():  # Strip leading/trailing whitespaces from username
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    if rows[1] == hashed_password:
                        print("Signed in successfully")
                        return True
        print("Failed to login, check your name or password")
        return False
    except Exception as e:
        print("Error:", e)
        return False

def register_new(username, password):
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open("auth.txt", "a") as f:
            f.write(f"{username},{hashed_password}\n")
            print("Registered successfully")
    except Exception as e:
        print("Error:", e)

def generate_keys(username):
    private_key_file = f"{username}_private.pem"
    public_key_file = f"{username}_public.pem"
    
    if not (os.path.isfile(private_key_file) and os.path.isfile(public_key_file)):
        publicKey , privateKey = rsa.newkeys(1024) #1024 bytes long
        with open(private_key_file, "wb") as f:
            f.write(privateKey.save_pkcs1("PEM"))

        with open(public_key_file, "wb") as f:
            f.write(publicKey.save_pkcs1("PEM"))

# check that the user is logged in then he will be able to send a message
def authentication(): 
    choice = input('Enter 1 to signIn or 2 to register \n')
    if choice == '1':
        username = input("Please enter your username :")
        password = input("Enter your password : ")
        isUser = SignIn(username, password, "auth.txt")
        generate_keys(username)  # Generate keys if they don't exist
        if isUser:
            with open (f"{username}_private.pem","rb") as f :
                private_key = rsa.PrivateKey.load_pkcs1(f.read())

            with open (f"{username}_public.pem","rb") as f :
                public_key = rsa.PublicKey.load_pkcs1(f.read())

            ############# sign the message with the owners of the private key ########
            message = open('message','rb').read()
            # hash the original message using SHA-256 algorithm
            #hash_value = rsa.compute_hash(message, "SHA-256")
            # add the message , private key for each user and the hashed value in the signature
            signature = rsa.sign(message, private_key, "SHA-256")
            with open(f"{username}_signature",'wb') as signature_file:
                signature_file.write(signature)
                signature_file.close()
            print("Your signature on the message is successfully created  ") 
            ## if we want to encrypt the message to check its validity alone
            encrypted_msg = rsa.encrypt(message, public_key)
            print("The encrypted message is", encrypted_msg)
            # Write the encrypted message to a file
            with open('encrypted_msg1','wb') as f:
                f.write(encrypted_msg)
                f.close()

        else:
            print("Wrong username or password")

    elif choice == '2':
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        register_new(username, password)
        authentication()
    
authentication()