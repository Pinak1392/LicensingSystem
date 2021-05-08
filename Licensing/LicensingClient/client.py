import requests
ip = "https://licenseprototype.herokuapp.com"


def createUser(email,num):
    #Make a request to the server
    r = requests.post(ip + '/create', data = {'email':email,'num':num})
    f = open("getKey.txt", "w")
    f.write(r.text)
    f.close()

def createKey(email,num):
    #Make a request to the server
    r = requests.post(ip + '/createKey', data = {'email':email,'num':num})
    if r.text != "True":
        print(r.text)

def getKey(getKey):
    #Make a request to the server
    r = requests.post(ip + '/getKey', data = {'getKey':getKey})
    if not r.text.startswith("ID:"):
        print(r.text)
        return
    f = open("keyfile.txt", "w")
    f.write(r.text)
    f.close()

def verify():
    #Open keyfile and split ID and key apart
    f = open("keyfile.txt", "r")
    keyInfoPT = f.read()
    f.close()

    #Split the names apart from the values
    keyInfo = keyInfoPT.split('\n')
    for i in range(len(keyInfo)):
        keyInfo[i] = keyInfo[i].split(':')

    r = requests.post(ip + '/verify', data = {'key':keyInfo[1][1]})
    newKey = r.text
    
    if newKey == 'error':
        print("Your key is unrecognised")
        return False
    
    if newKey == 'expired':
        print("Your license has expired")
        return False

    #Create new key file
    oldkey = keyInfo[1][1]
    keyInfo[1][1] = newKey
    keyInfoPT = keyInfo[:]

    for i in range(len(keyInfoPT)):
        keyInfoPT[i] = ':'.join(keyInfoPT[i])
    keyInfoPT = '\n'.join(keyInfoPT)


    r = requests.post(ip + '/newKeyReceived', data = {'id':keyInfo[0][1], 'oldkey':oldkey, 'key':keyInfo[1][1]})
    if r.text == 'received':
        
        #Write new key file
        f = open("keyfile.txt", "w")
        f.write(keyInfoPT)
        f.close()

        return True

    print('server verification timeout')
    return False