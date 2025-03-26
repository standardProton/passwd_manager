# Simple Password Manager

This is a simple python script that securely manages your passwords offline. Simply remember a main password that decrypts the rest of the passwords. This tool can be set up with a command line alias to quickly retrieve your passwords through a terminal.

To set up, run `pip install -r requirements.txt`

A salt will automatically be generated in the `salt` file, and the encrypted data will be stored in `pwstore`. No decrypted password data is ever written to the disk.

## Command list:

| Command | Description |
| - | - |
| get \<name\> | Copies the password for this site name to the clipboard |
| print \<name\> | Prints the password for this site to stdout |
| set \<name\> \<password\> | Updates the password for a site name |
| comment \<name\> \<new comment\> | Sets the comment for a site name, useful for any additional info to store |
| delete \<name\> | Remove a site name from password storage |
| list | List all entered site names |

The main password must be entered first before any of these commands can be accessed.

## Example

Using `pw` as a command line alias to run passwd.py with arguments, you could do:

~~~
pw --set gmail Password_Here
pw --comment gmail username=you@gmail.com
~~~

(The dashes are not reqiured, just helpful for conventional cmd format)

The password could then be retrieved with `pw gmail` or `pw get gmail` after entering the main password