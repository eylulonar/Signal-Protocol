import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib
import re
import json

API_URL = 'http://10.92.52.175:5000/'

stuID =  25357  ## Change this to your ID number

#Send Public Identitiy Key Coordinates and corresponding signature
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

#Send the verification code
def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

#Send SPK Coordinates and corresponding signature
def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

#Send OTK Coordinates and corresponding hmac
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
#Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

#Functions
def key_gen(curve): #key generation function. First it gets a random number as private key(sA) then we use this private key to generate public key QA(x,y)
    P = curve.generator
    ord = curve.order
    rand = random.randint(1, ord-1)
    sA = rand
    QA = sA * P
    return sA, QA

""" def SignGen(m, curve, s_A): //function to sign the id
    n = curve.order
    P = curve.generator
    k = random.randint(1, n-2)   //random number k is generated
    R = k * P    //scalar multiplication of k and P
    r = R.x % n  //reduce to mod n
    hx = SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+ m.to_bytes((m.bit_length()+7)//8, byteorder='big'))
    h = int.from_bytes(hx.digest(), byteorder='big') % n
    s = (k - s_A * h ) % n
    return s, h      //return signature tuple """ 

def SignGen2(m, curve, s_A): #function to sign the m which is the concatenation of SPK.x and SPK.y in bytes
    n = curve.order
    P = curve.generator
    k = random.randint(1, n-2) #random number k is generated 
    R = k * P
    r = R.x % n
    hx = SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big') + m) #implement SHA3_256 with r || m
    h = int.from_bytes(hx.digest(), byteorder='big') % n
    s = (k - s_A * h ) % n #find s
    return s, h #return signature tuple

def verify(h, s, spk_x, spk_y, curve, IKey_Ser): #verify the signature tuple returned from server
    n = curve.order
    P = curve.generator
    big_V = (s * P) + (h * IKey_Ser)
    v = big_V.x % n
    mx = SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big') + spk_x.to_bytes((spk_x.bit_length()+7)//8, byteorder='big')+ spk_y.to_bytes((spk_y.bit_length()+7)//8, byteorder='big'))
    hx= int.from_bytes(mx.digest(), byteorder='big') % n
    #we will accept the signature if hx=h
    if(hx==h):
        print("Verified")
    else:
        print("Not verified")

def generateHMAC(spk_x,spk_y,curve,spka_priv):#function to generate hmac keys
    QB = Point(spk_x, spk_y, curve)
    T = spka_priv * QB
    u = b'NoNeedToRideAndHide'
    U= T.x.to_bytes((T.x.bit_length()+7)//8, byteorder='big') + T.y.to_bytes((T.y.bit_length()+7)//8, byteorder='big') + u #concatenate x +y + u
    HMAC1 = SHA3_256.new(U).digest() #create SHA_256 instance
    print("T is :", T)
    print("U is : ", U)
    print("HMAC key is: ", HMAC1)
    print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    return(HMAC1)

def Otk(HMAC1, q_a):
    x= q_a.x
    y=q_a.y
    message= x.to_bytes((x.bit_length()+7)//8, byteorder='big') + y.to_bytes((y.bit_length()+7)//8, byteorder='big') #concatenate x and y
    print("x and y coordinates of the OTK converted to bytes and concatanated message", message)
    print(" ")
    hashed = HMAC.new(HMAC1,message, digestmod=SHA256).hexdigest() #create HMAC instance with key, message and digestmod
    print("hmac is calculated and converted with 'hexdigest()': ",hashed)
    print(" ")
    return hashed

def GenerateOTK(spk_x,spk_y,curve,spka_priv):
    HMAC=generateHMAC(spk_x,spk_y,curve,spka_priv) #generate key
    #create 11 keys to register
    for i in range(11):
        s_a, q_a= key_gen(curve) #create private and public key pairs 
        print(i,"th key "," Private part: ", s_a, " Public X : ", q_a.x, " Private Y : ", q_a.y)
        print(" ")
        hash=Otk(HMAC,q_a) #returns calculated hmac
        OTKReg(i,q_a.x,q_a.y,hash) #register the otk's
        print('********')
        print(" ")




#Curve information
curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

""" 2.1 Identity Key """
    #ReadMe
""" Identity keys s_a (private) and q_a(public) are implemented with the use of key_gen() function. 
    Then, id=25357 is signed with the private key.
    Then it is registered to system. We saved the q_a, and s_a with h and s. They are printed. """
#s_a, q_a =key_gen(curve)
#s, h =SignGen(25357,curve, s_a)
#print(s_a, q_a, s, h)
#IKRegReq(h,s,q_a.x, q_a.y)  //registered succesfully
#IKRegVerify(427322)        //server sends a code via email
h_id=56365705298335195759583071608191261490605288257504072428239477159586215640934
s_id=72181175799194244208032321844652834437618900902501414399702671064129660880699
pubx_id= 3501608331694901529767037919038527588451635528381889850949684132448234649192
puby_id=102536283075277210917065536512800542547415855086993078624602009704161113357971
print("Identitiy Key is created")
print("Key is a long term key and shouldn't be changed and private part should be kept secret. But this is a sample run, so here is my private IKey: 57482405858864034497815686426091936426005352169501135761449175784315194678703")
print("My ID number is 25357. Converted my ID to bytes in order to sign it:", stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'))
print("Signature of my ID number is:")
print("h= ",h_id)
print("s= ", s_id)
print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h_id,s_id,pubx_id,puby_id)
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("Received the verification code through email")
print("Enter verification code which is sent to you:")
print("Sending the verification code to server via IKRegVerify() function in json format") 
IKRegVerify(427322)
print("Our signature has been registered succesfully.")
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    #Part 2.1 finished

""" 2.2 Signed Pre-key """
    #ReadMe
""" Signed keys spka_priv and spka_pub is calculated using key_gen() function.
Then the concatenation of spka_pub.x and spka_pub.y is calculated to send to SignGen2() function as message. 
Then they are registered to server.
We save the response of the server. """

print("Generating SPK...")
spka_priv, spka_pub = key_gen(curve)
print("Private SPK: ", spka_priv)
print("Public SPK-X: ", spka_pub.x)
print("Public SPK-Y: ", spka_pub.x)
conca= spka_pub.x.to_bytes((spka_pub.x.bit_length()+7)//8, byteorder='big')+ spka_pub.y.to_bytes((spka_pub.y.bit_length()+7)//8, byteorder='big')
print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them result will be like:")
print(conca)
s,h =SignGen2(conca,curve,57482405858864034497815686426091936426005352169501135761449175784315194678703)
print("Signature of SPK is:")
print("h = ", h, "s = ", s)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")
spk_x, spk_y, h, s = SPKReg(h,s,spka_pub.x,spka_pub.y)
print("if server verifies the signature it will send its SPK and corresponding signature. If this is the case SPKReg() function will return those")
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("Server's SPK Verification")
print("Recreating the message(SPK) signed by the server. Verifying the server's SPK. If server's SPK is verified we can move to the OTK generation step")
print("Is SPK verified?:")
verify(h,s,spk_x,spk_y, curve, IKey_Ser)
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
# print(h,s,spk_x,spk_y)

""" 2.3 Registration of OTKs """
    #ReadMe
""" A hash-based MAC (HMAC) function is used to create HMAC keys.Then, we generate 10 one-time public and private keypairs. """
print("Creating HMAC key (Diffie Hellman")
GenerateOTK(spk_x,spk_y,curve,spka_priv)


""" Reseting Functions:
Before submitting the file, SPK and OTK's are resetted. When you run the code it will generate new SPK and OTK from scratch. 
The steps willl be printed. IK is not resetted, the registered IK's information has been saved to print.
"""
#ResetSPK(h_id,s_id)
#ResetOTK(h_id,s_id)
#ResetIK(861073)
