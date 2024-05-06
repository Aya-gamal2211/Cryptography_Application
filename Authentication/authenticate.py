import hashlib

def verify(username, password, filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                rows = line.strip().split(',')
                if rows[0] == username:
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

register_new("shimo", "test1")
print(verify("shimo", "test1", "auth.txt"))
