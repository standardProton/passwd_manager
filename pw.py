import os, hashlib, base64, random, json, time, subprocess, sys
from cryptography.fernet import Fernet
from getpass import getpass

HELP_STR = "Commands: --set, --get, --print, --list, --delete"

def readSalt() -> str:
    if (isFileEmpty('salt')):
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
        salt = ''.join([alphabet[random.randint(0, len(alphabet)-1)] for _ in range(32)])
        with open('salt', 'w') as f: f.write(salt + "\n### DO NOT CHANGE ###")
        return salt
    else: 
        with open('salt', 'r') as f:
            nacl = f.read().split('\n')[0]
            if (len(nacl) < 16): print("Warning: Salt should be at least 16 chars (current length is %s)" % len(nacl))
            return nacl

def openPasswords(fernet) -> dict:
    if (isFileEmpty('pwstore')): return {}
    else:
        while True:
            try:
                with open("pwstore", 'r') as f:
                    decrypted = fernet.decrypt(f.read())
                    return json.loads(decrypted)
            except Exception as ex: return None

def writePasswords(vals: dict, fernet: Fernet):
    print("write:")
    print(json.dumps(vals))
    encrypted = fernet.encrypt(json.dumps(vals).encode('utf-8')).decode()
    with open('pwstore', 'w') as f: f.write(encrypted)

def tryPassword(nacl: str) -> dict:
    fernet = getFernet(nacl, getpass("Enter your password: "))
    vals = openPasswords(fernet)
    if (vals is None):
        print("Incorrect password.")
        return tryPassword(nacl)
    else: return vals, fernet

def isFileEmpty(path: str) -> bool:
    if (not os.path.isfile(path)): return True
    with open(path, 'r') as f: return len(f.read()) == 0

def getFernet(nacl, pw):
    pwhash = hashlib.sha256(base64.b64encode((nacl + pw).encode('utf-8'))).hexdigest()
    return Fernet(base64.urlsafe_b64encode(bytes.fromhex(pwhash)[0:32]))

def setClipboard(s: str):
    subprocess.check_call('echo %s | clip' % s, shell=True)

def printPw(key, vals, copy=True):
    if (key in vals): 
        if (copy):
            setClipboard(vals[key])
            print("Password copied to clipboard!")
        else: print(vals[key])
    else: print("Unknown site name")

if __name__ == "__main__":
    with_sysargs = len(sys.argv) > 1
    if (with_sysargs and sys.argv[1].lower() == '--help'): 
        print(HELP_STR)
        quit()

    nacl = readSalt()
    vals = {}
    fernet = None
    if (isFileEmpty('pwstore')):
        with open("pwstore", "w") as f: pass
        while True:
            pw = input("Enter a new password: ")
            print("\nConfirm new password: %s" % pw)
            confirm = input("[Y/n]: ").lower()
            if (confirm == "y" or confirm == "yes"):
                fernet = getFernet(nacl, pw)
                break
    else: vals, fernet = tryPassword(nacl)

    if (not with_sysargs): 
        print("Password accepted!")
        print(HELP_STR)
    first = True

    while first or not with_sysargs:
        args = sys.argv[1:] if with_sysargs else input("> ").split(" ")
        first = False
        if (len(args) == 0): continue
        args[0] = args[0].lower()

        if (args[0] == 'list' or args[0] == '--list'):
            keys = vals.keys()
            print("%s Password key(s):" % len(keys))
            for key in keys: print("- %s" % key)
        # elif (args[0] == 'set'):
        #     if (len(args) == 2): print("Format: set <name> <new password>")
        elif (args[0] == '--get' or args[0] == 'get'): printPw(args[1].lower(), vals, copy=True)
        elif (args[0] == '--print' or args[0] == 'print'): printPw(args[1].lower(), vals, copy=False)
        elif (args[0] == '--set' or args[0] == 'set'):
            if (len(args) < 3): print("Usage: set <name> <new password>")
            else:
                key = args[1].lower()
                
        else: printPw(args[0].lower(), vals, copy=True)
        
    print("vals:")
    print(vals)