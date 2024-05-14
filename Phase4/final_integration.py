import hashlib
import rsa
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
def hashing_sha256(text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text)
    hashed_key = sha256_hash.digest()
    return hashed_key
    
# AES Encryption and Decryption
def encrypt_with_aes(message, key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext
def decrypt_with_aes(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    ciphertext = ciphertext[16:]  # Extract the actual ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
# check that the user is logged in then he will be able to send a message
shared_secret_key = os.urandom(32)  # Generate a random shared secret key

def Send_message(): 
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
            receiver_username = input(("enter the receiver name : "))
            message = input("enter the message you want to send : ")
            with open('msg','wb') as f:
                f.write(message.encode())
                f.close()

            # Generate a random shared secret key
            shared_secret_key = os.urandom(32)
            
            # Encrypt the message with AES using the shared secret key
            encrypted_message = encrypt_with_aes(message.encode(), shared_secret_key)

            # Encrypt the shared secret key with receiver's public key
            with open(f"{receiver_username}_public.pem", "rb") as f:
                receiver_public_key = rsa.PublicKey.load_pkcs1(f.read())
            encrypted_shared_secret = rsa.encrypt(shared_secret_key, receiver_public_key)

            # add the message, private key for each user, and the hashed value in the signature
            message = open('msg','rb').read()
            signature = rsa.sign(encrypted_message, private_key, "SHA-256")
            with open(f"{username}_signature",'wb') as signature_file:
                signature_file.write(signature)
                signature_file.close()
                
            print("Your signature on the message is successfully created") 
            print("Encrypted Message:", encrypted_message) 
            # Call receive_message function to decrypt and verify the message
            receive_message(receiver_username, username, encrypted_message, encrypted_shared_secret, signature)
        else:
            print("Wrong username or password")

    elif choice == '2':
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        register_new(username, password)
        Send_message(username, receiver_username, message)

def receive_message(receiver_username, sender_username, encrypted_message, encrypted_shared_secret, signature):
    # Load receiver's private key
    with open(f"{receiver_username}_private.pem", "rb") as f:
        receiver_private_key = rsa.PrivateKey.load_pkcs1(f.read())

    # Load sender's public key
    with open(f"{sender_username}_public.pem", "rb") as f:
        sender_public_key = rsa.PublicKey.load_pkcs1(f.read())

    # Decrypt the shared secret key using receiver's private key
    decrypted_shared_secret = rsa.decrypt(encrypted_shared_secret, receiver_private_key)

    # Decrypt the message using the decrypted shared secret key
    decrypted_message = decrypt_with_aes(encrypted_message, decrypted_shared_secret)

    # Verify the signature of the message using sender's public key
    try:
        rsa.verify(encrypted_message, signature, sender_public_key)
        print("Signature verification successful")
        print("Decrypted Message:", decrypted_message.decode())
    except rsa.VerificationError:
        print("Signature verification failed")

Send_message() # Replace "receiver_username" with the actual receiver's username
