
import hashlib

def hashing_sha256(text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text)
    hashed_key = sha256_hash.digest()
    return hashed_key

def hashing_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text)
    hashed_key = md5_hash.digest()
    return hashed_key


data_to_hash = b"Hello World"
hashed_sha256 = hashing_sha256(data_to_hash)
hashed_md5 = hashing_md5(data_to_hash)

print("list of available hashing algorithms : \n",hashlib.algorithms_available)
print("SHA-256 Hash:", hashed_sha256)
print("MD5 Hash:", hashed_md5)