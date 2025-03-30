import os, hashlib, base64, random, json, sys, pyperclip, secrets
from cryptography.fernet import Fernet
from getpass import getpass

SECURITY_CHARS = 0 #the number of chars at the end of pw to print to console, rather than entire password put onto clipboard (recommended no more than 3)
GENERATE_LENGTH = 24
HELP_STR = """
Command list:
set <name> <password>: Set/update the password for a site name
get <name>: Copy a password to clipboard
print <name>: Print a password to stdout
comment <name> <new comment>: Set the comment for a site name
list: List all site names
delete <name>: Delete a password for a site name
generate <name>: Create a new password for site
setmainpw <new password>: Change the main password
"""

def readSalt() -> str:
    if (isFileEmpty('salt')): #generate new salt
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

def getPassword(key, vals):
    password, comments = None, None
    if (key in vals):
        if (isinstance(vals[key], dict)): 
            if ('password' in vals[key]): password = vals[key]['password']
            else: print("Malformatted key store for %s!" % key)
            if ('comment' in vals[key]): comments = vals[key]['comment']
        elif (isinstance(vals[key], str)): password = vals[key] #fallback
    return password, comments

def printPw(key, vals, copy=True):
    if (key in vals): 
        password, comments = getPassword(key, vals)
        if (comments is not None): print("Comment: %s" % comments)
        if (copy):
            if (SECURITY_CHARS <= 0):
                pyperclip.copy(password)
                print("Password copied to clipboard!")
            else:
                copy_chars = password[:-SECURITY_CHARS]
                end_chars = password[-SECURITY_CHARS:]
                pyperclip.copy(copy_chars)
                print("Paste first portion, THEN type: %s" % end_chars)
        else: print(password)
    else: print("Unknown site name")

def setComment(key, comment, vals):
    if not (key in vals): return
    password, old_comments = getPassword(key, vals)
    vals[key] = {
        'password': password,
        'comment': comment
    }
    return vals, old_comments

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
    else: 
        vals, fernet = tryPassword(nacl)
        if (not with_sysargs): print("Password accepted!")
    if (not with_sysargs): print("Type ? for a list of commands")
    first = True

    while first or not with_sysargs:
        args = sys.argv[1:] if with_sysargs else input("> ").split(" ")
        first = False
        if (len(args) == 0): continue
        args[0] = args[0].lower().replace('-', '')

        if (args[0] == '?' or args[0] == 'help'): print(HELP_STR)
        elif (args[0] == 'list'):
            keys = vals.keys()
            print("%s password key(s):" % len(keys))
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
            old_pw, comment = getPassword(key, vals)
            vals[key] = {
                'password': pw,
                'comment': comment
            }
            writePasswords(vals, fernet)
            print("Successfully set password for %s!" % key)

        elif (args[0] == 'comment'):
            if (len(args) < 3): 
                print("Usage: comment <name> <comment>")
                continue
            key = args[1].lower()
            if not (key in vals): 
                print("Unknown site name '%s'" % key)
                continue
            comment = args[2]
            if (not with_sysargs): comment = ' '.join(args[2:]).strip()
            vals, old_comment = setComment(key, comment, vals)
            writePasswords(vals, fernet)
            if (old_comment is not None): print("Old comment for %s: %s" % (key, old_comment))
            print("New comment for %s: %s" % (key, comment))

        elif (args[0] == 'delete' or args[0] == 'del'):
            if (len(args) < 2): 
                print("Usage: del <name>")
                continue
            key = args[1].lower()
            del vals[key]
            writePasswords(vals, fernet)
            print("Deleted %s!" % key)

        elif (args[0] == 'generate' or args[0] == 'gen'):
            if (len(args) < 2):
                print("Generate a password for a new site. Usage: generate <name>")
                continue
            key = args[1].lower()
            if (key in vals):
                print("Error: This name is already taken, use 'delete' or 'set' to change")
                continue
            alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()'
            pw = ''.join([alphabet[secrets.choice(range(0, len(alphabet)))] for _ in range(GENERATE_LENGTH)])
            vals[key] = pw
            writePasswords(vals, fernet)
            print("Successfully generated new password!")
            printPw(key, vals, copy=True)

        elif (args[0] == 'setmainpw' or args[0] == 'passwd'):
            if (len(args) < 2): 
                print("Change the main password. Usage: passwd <new password>")
                continue
            print("Confirm new password: %s" % args[1])
            while True:
                confirm = input("[Y/n]: ").lower()
                if (confirm == 'y' or confirm == 'yes'):
                    fernet = getFernet(nacl, args[1])
                    writePasswords(vals, fernet)
                    print("Password updated!")
                    break
                elif (confirm == 'n' or confirm == 'no'):
                    print("Operation cancelled.")
                    break
        
        elif (args[0] == 'exit' or args[0] == 'quit'): break
        else: printPw(args[0].lower(), vals, copy=True)
        print('')