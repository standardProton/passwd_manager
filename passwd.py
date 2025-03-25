import os, hashlib, base64, random, json, time, subprocess, sys
from cryptography.fernet import Fernet
from getpass import getpass

HELP_STR = "Commands: --set, --get, --print, --list, --delete"
OS = "windows" #valid: 'windows', 'linux', 'mac'
SECURITY_CHARS = 0 #the number of chars at the end of pw to print to console, rather than entire password put onto clipboard

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
    cmd = None
    if (OS == 'linux'): cmd = 'echo -n %s| xclip'
    elif (OS == 'mac'): cmd = 'echo -n %s| pbcopy' #TODO: test this on a mac or vm
    else: cmd = 'echo | set /p=%s|clip'
    subprocess.check_call(cmd % s.strip(), shell=True)

def printPw(key, vals, copy=True):
    if (key in vals): 
        if (copy):
            if (SECURITY_CHARS <= 0):
                setClipboard(vals[key])
                print("Password copied to clipboard!")
            else:
                copy_chars = vals[key][:-SECURITY_CHARS]
                end_chars = vals[key][-SECURITY_CHARS:]
                setClipboard(copy_chars)
                print("Paste first portion, THEN type: %s" % end_chars)
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
        args[0] = args[0].lower().replace('--', '')

        if (args[0] == 'list'):
            keys = vals.keys()
            print("%s Password key(s):" % len(keys))
            for key in keys: print("- %s" % key)
        elif (args[0] == 'get'): printPw(args[1].lower(), vals, copy=True)
        elif (args[0] == 'print'): printPw(args[1].lower(), vals, copy=False)
        elif (args[0] == 'set' or args[0] == 'put'):
            if (len(args) < 3): 
                print("Usage: set <name> <new password>")
                continue
            key = args[1].lower()
            pw = args[2]
            if not with_sysargs: pw = ' '.join(args[2:]).strip() #concat all args if using built-in shell
            vals[key] = pw
            writePasswords(vals, fernet)
            print("Set password for %s!" % key)
        elif (args[0] == 'delete' or args[0] == 'del'):
            if (len(args) < 2): 
                print("Usage: del <name>")
                continue
            key = args[1].lower()
            del vals[key]
            writePasswords(vals, fernet)
            print("Deleted %s!" % key)
        elif (args[0] == 'exit' or args[0] == 'quit'): break
        else: printPw(args[0].lower(), vals, copy=True)
        print('')