from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
import os

# Function to generate ECC key pair and save them to files
def generate_ecc_keys():
    # Generate ECC key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Export private key
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Export public key
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys to files
    with open("private_key.pem", "wb") as f:
        f.write(pem_private_key)

    with open("public_key.pem", "wb") as f:
        f.write(pem_public_key)

# Function to perform ECDH key exchange
def perform_ecdh_key_exchange(private_key_path, public_key_path):
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Perform ECDH key exchange
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    return shared_key

# Function to encrypt a message using AES in EAX mode
def encrypt_message(message, shared_key):
    # Derive encryption key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption key",
    )
    encryption_key = hkdf.derive(shared_key)

    # Generate a random nonce of appropriate length (between 7 and 13 bytes)
    nonce_length = 12  # Choose a length between 7 and 13
    nonce = os.urandom(nonce_length)

    # Encrypt message using AES in CCM mode
    cipher = AESCCM(encryption_key)
    ciphertext = cipher.encrypt(nonce, message.encode(), None)

    # Return nonce and ciphertext
    return nonce, ciphertext

# Function to decrypt a message using AES in EAX mode
def decrypt_message(nonce, ciphertext, shared_key):
    # Derive decryption key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption key",
    )
    decryption_key = hkdf.derive(shared_key)

    # Decrypt message using AES in CCM mode
    cipher = AESCCM(decryption_key)
    decrypted_data = cipher.decrypt(nonce, ciphertext, None)

    # Return decrypted message
    return decrypted_data.decode()

# Generate ECC keys and save them to files
generate_ecc_keys()

# Perform ECDH key exchange
shared_key = perform_ecdh_key_exchange("private_key.pem", "public_key.pem")

# Encrypt a message using AES in CCM mode
message = "Welcome to security world"
nonce, ciphertext = encrypt_message(message, shared_key)

print("Original message:", message)

# Print out the encrypted message
print("Encrypted message (in bytes):")
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)

# Decrypt the message using AES in CCM mode
decrypted_message = decrypt_message(nonce, ciphertext, shared_key)
print("Decrypted message:", decrypted_message)
