## Simple Password Manager

This is a simple python script that securely manages your passwords offline. Simply remember a main password that decrypts the rest of the passwords. This tool can be set up with an alias to retrieve your passwords through the command line on your system. 

To set up, run `pip install -r requirements.txt`

A salt will automatically be generated in the `salt` file, and the encrypted data will be stored in `pwstore`. No decrypted password data is ever written to the disk.