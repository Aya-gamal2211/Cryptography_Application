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

# print(verify("shimo", "test1", "auth.txt"))
def generate_keys(username):
    private_key_file = f"{username}_private.pem"
    public_key_file = f"{username}_public.pem"
    
    if not (os.path.isfile(private_key_file) and os.path.isfile(public_key_file)):
        publicKey , privateKey = rsa.newkeys(1024) #1024 bytes long
        with open(private_key_file, "wb") as f:
            f.write(privateKey.save_pkcs1("PEM"))

        with open(public_key_file, "wb") as f:
            f.write(publicKey.save_pkcs1("PEM"))

# check that the user is logged in
def authentication(): 
    choice = input('Enter 1 to signIn or 2 to register \n')
    if choice == '1':
        username = input("Please enter your username :")
        password = input("Enter your password: ")
        isUser = SignIn(username, password, "auth.txt")
        generate_keys(username)  # Generate keys if they don't exist

        if isUser:
            with open (f"{username}_private.pem","rb") as f :
                private_key = rsa.PrivateKey.load_pkcs1(f.read())

            with open (f"{username}_public.pem","rb") as f :
                public_key = rsa.PublicKey.load_pkcs1(f.read())

            ############# sign the message with the owners of the private key ########
            message = open('message','rb').read()
            encrypted_msg = rsa.encrypt(message, public_key)
            print("The encrypted message is", encrypted_msg)
            # Write the encrypted message to a file
            with open('encrypted_msg1','wb') as f:
                f.write(encrypted_msg)
                f.close()
            hash_value = rsa.compute_hash(encrypted_msg, "SHA-256")
            signature = rsa.sign(encrypted_msg, private_key, "SHA-256")
            with open('signature_file','wb') as signature_file:
                signature_file.write(signature)
            print("Your signature on the message is successfully created  ")
        else:
            print("Wrong username or password")

    elif choice == '2':
        #f.truncate()
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        register_new(username, password)
        authentication()
    
authentication()