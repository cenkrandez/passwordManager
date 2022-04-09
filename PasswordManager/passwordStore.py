from cryptography.fernet import Fernet 
import hashlib
import getpass

"""
def write_key():
	key = Fernet.generate_key()
	with open("key.key", "wb") as key_file:
		key_file.write(key)"""

masterPassword_hash = "WRITE AN MD5 HASH KEY HERE"

myInputKey = getpass.getpass('Enter your master password: ')

myInputHash = hashlib.md5(myInputKey.encode())

finalHash = myInputHash.hexdigest()

if masterPassword_hash != finalHash:
	print("Please enter the correct master password")
	quit()

def load_key():
	file = open("key.key" ,"rb")
	key = file.read()
	file.close()
	return key



key = load_key() 
fer = Fernet(key)

def view():
	with open("passwords.txt","r") as f:
		for lines in f.readlines():
			data = lines.rstrip()
			user, passw = data.split("|")
			print("User:", user, "| Password: ", fer.decrypt(passw.encode()).decode())
def add():
	name = input("Account name: ")
	pwd = input("Password: ")

	with open("passwords.txt" , "a") as f:
		f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")


while True:
	mode = input("Add password or view the existing ones or q for quit ").lower()

	if mode == "q":
		break

	elif mode == "view":
		view()
	elif mode == "add":
		add()
	else:
		print("Please write a valid option")
		continue

print("See you next time")