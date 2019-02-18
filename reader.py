from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import binascii, re, hashlib, urllib, urllib2, os



def crypt(data):
        privatekey = RSA.importKey(open('privatekey.txt','rb').read())
        publickey = privatekey.publickey()
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






def messege(secdata):
        global c1,c2,c3
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





def ck():
        ckey = open('Keys/Chatid.txt', 'r')
        cid = str(int("0x"+"".join("{:02x}".format(ord(c)) for c in ckey.read()),0))[390:398]
        print "Your chatid:" + cid
        return cid





def have(prevsec,secdata):
  try:
    f = urllib.urlopen(c1)
    fi = urllib.urlopen("http://hcbf.000webhostapp.com/firststart.txt")
    prevsec = f.read()
    fid = fi.read()
    pro = len(secdata)
    print pro
    if pro == 767:
      if int(fid) == int(cid):
        if prevsec != secdata:
                f = urllib.urlopen(c1)
                
                a = secdata 
                secdata = f.read()
                if a != secdata:
                        os.system('cls')
                        print decrypt(secdata) + "\n"
  except:
        print decrypt(secdata)
        pass  

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

ck()

secdata = crypt(":")
messege(secdata)
f = urllib.urlopen(c1)
secdata = f.read()
prevsec = f.read()





while True:
  #if prevsec == secdata:
  #  time.sleep(1)
  have(prevsec,secdata)

