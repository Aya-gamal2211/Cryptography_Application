from cryptography.hazmat.primitives.asymmetric import rsa

def RSAKey():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
    public_key = private_key.public_key()
    
    return public_key, private_key
