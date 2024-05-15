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
        # Generate keys only if they don't already exist
        generate_keys(username)
        
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
    
# AES Encryption and Decryption with EAX mode
def encrypt_with_aes(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce + tag + ciphertext

def decrypt_with_aes(ciphertext, key):
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    actual_ciphertext = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
    return plaintext

def Send_message(): 
    choice = input('Enter 1 to signIn or 2 to register \n')
    if choice == '1':
        username = input("Please enter your username :")
        password = input("Enter your password : ")
        isUser = SignIn(username, password, "auth.txt")
        if isUser:
            with open(f"{username}_private.pem", "rb") as f:
                private_key = rsa.PrivateKey.load_pkcs1(f.read())
            with open(f"{username}_public.pem", "rb") as f:
                public_key = rsa.PublicKey.load_pkcs1(f.read())

            receiver_username = input("Enter the receiver name : ")
            receiver_public_key_file = f"{receiver_username}_public.pem"
            if not os.path.isfile(receiver_public_key_file):
                print(f"Error: Receiver's public key not found. Ask {receiver_username} to register.")
                return
            message = input("Enter the message you want to send : ")
            if not message:
                print('Please enter a message, it cannot be empty.')
                return
            
            message_bytes = message.encode()  # Convert message to bytes
            shared_secret_key = os.urandom(32)

            # Encrypt the message with AES using the shared secret key
            encrypted_message = encrypt_with_aes(message_bytes, shared_secret_key)

            # Encrypt the shared secret key with receiver's public key
            with open(receiver_public_key_file, "rb") as f:
                receiver_public_key = rsa.PublicKey.load_pkcs1(f.read())
            encrypted_shared_secret = rsa.encrypt(shared_secret_key, receiver_public_key)

            # Add the message, private key for each user, and the hashed value in the signature
            signature = rsa.sign(encrypted_message, private_key, "SHA-256")
            with open(f"{username}_signature", 'wb') as signature_file:
                signature_file.write(signature)
            with open("encrypted_msg", 'wb') as encrypted_msg:
                encrypted_msg.write(encrypted_message)

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
        Send_message()

def receive_message(receiver_username, sender_username, encrypted_message, encrypted_shared_secret, signature):
    # Load or generate receiver's private key
    private_key_file = f"{receiver_username}_private.pem"
    public_key_file = f"{receiver_username}_public.pem"
    
    if not (os.path.isfile(private_key_file) and os.path.isfile(public_key_file)):
        print("Receiver's keys not found. Generating new keys...")
        generate_keys(receiver_username)

    with open(private_key_file, "rb") as f:
        receiver_private_key = rsa.PrivateKey.load_pkcs1(f.read())
        
    # Load sender's public key
    sender_public_key_file = f"{sender_username}_public.pem"
    if not os.path.isfile(sender_public_key_file):
        print(f"Error: Sender's public key not found. Ask {sender_username} to register.")
        return

    with open(sender_public_key_file, "rb") as f:
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

Send_message()
