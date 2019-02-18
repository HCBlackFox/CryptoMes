from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from termcolor import colored
import binascii, re, hashlib, urllib, urllib2, os

def keygen():
	
	privatekey = RSA.generate(2048)
	f = open('privatekey.txt','wb')
	f.write(bytes(privatekey.exportKey('PEM'))); f.close()
	publickey = privatekey.publickey()
	f = open('publickey.txt','wb')
	f.write(bytes(publickey.exportKey('PEM'))); f.close()
	print("Keys generate succesfuly :)")
	pass



	




def crypt(data):
	
	publickey = RSA.importKey(open(way,'rb').read())
	cipherrsa = PKCS1_OAEP.new(publickey)
	secdata = cipherrsa.encrypt(data)
	secdata = ":".join("{:02x}".format(ord(c)) for c in secdata)
	return secdata







def decrypt(secdata):
	secdata = binascii.unhexlify(re.sub(':', '',secdata))
	privatekey = RSA.importKey(open('privatekey.txt','rb').read())
	cipherrsa = PKCS1_OAEP.new(privatekey)
	decdata = cipherrsa.decrypt(secdata)
	return decdata







def chid(cid):
        name =  "1"
        data = {
                "age" : cid
                
                }
        encoded_data = urllib.urlencode(data)
        content = urllib2.urlopen(c2,
        encoded_data)   


def ck():
		ckey = open("Keys/Chatid.txt", 'r')
		cid = str(int("0x"+"".join("{:02x}".format(ord(c)) for c in ckey.read()),0))[390:398]
		print "Your chatid:" + cid
		return cid


def messege(secdata):

	f = urllib.urlopen(c1)
        prevsec = f.read()
	name =  "1"
	data = {
        	"name" : secdata
        	
       		}
	encoded_data = urllib.urlencode(data)
	content = urllib2.urlopen(c3,
        encoded_data)
 	
	return prevsec
os.system('cls')
#___________________________________________________________________________________________________________________________





prevsec = 1
secdata = 1






#___________________________________________________________________________________________________________________________
print "Which channel to use?(1/2)"

sys = raw_input(":>")
if sys == '1':
	c1 = "http://hcbf.000webhostapp.com/counter1.txt"
	c2 = "http://hcbf.000webhostapp.com/1rsa1.php"
	c3 = "http://hcbf.000webhostapp.com/1rsa.php"
if sys == '2':
	c1 = "http://hcbf.000webhostapp.com/counter.txt"
	c2 = "http://hcbf.000webhostapp.com/rsa1.php"
	c3 = "http://hcbf.000webhostapp.com/rsa.php"


print "Do you want to generate RSA-keys,for this session?(1-yes,2-no) \n"


key = raw_input(":>")
if key == "1":
	keygen()


os.system("start reader.exe")

print "Write the full path to the public key of your interlocutor \n"
way = raw_input(":>")

print "What is your nickname? \n"
nick = raw_input(":>")


while True:
	os.system('cls')
	secdata = crypt(nick + ":" + raw_input("Message:>"))
	chid(ck())
	prevsec = messege(secdata)
	




