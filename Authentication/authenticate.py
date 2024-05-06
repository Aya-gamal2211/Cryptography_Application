
def verify(username,password,filename):
    try:
        password = password+"\n"
        with open(filename,'r') as file:
            lines =file.readlines()
            for line in lines:
                rows =line.split(',')
                if(rows[0]== username and rows[1]== password):
                    print("signed in successfully")
                    return True
                    
    except:
        print(Exception)
    print("failed to login , check your name or password")
    return False

print(verify("shaimaa","12345","auth.txt"))