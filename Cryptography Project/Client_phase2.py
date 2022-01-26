
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
import re
import json

API_URL = 'http://10.92.52.175:5000/'

stuID =  25357  ## Change this to your ID number
curve = Curve.get_curve('secp256k1')
n = curve.order
P = curve.generator

#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

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

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#get your messages. server will send 1 message from your inbox 
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

def generateKS(otk_priv, ephemeralPub):
    T= otk_priv * ephemeralPub
    u = b'MadMadWorld'
    U= T.x.to_bytes((T.x.bit_length()+7)//8, byteorder='big') + T.y.to_bytes((T.y.bit_length()+7)//8, byteorder='big') + u #concatenate T with u
    KS = SHA3_256.new(U).digest() #KS = SHA3_256(U)
    print("T is: ", T)
    print("U is: ", U)
    print("KS is: ", KS)
    print("")
    return KS

#function to generate KDF
def generateKDF(KS):
    u1 = b'LeaveMeAlone'
    u2 = b'GlovesAndSteeringWheel'
    u3 = b'YouWillNotHaveTheDrink'
    list_of_keys= [] #we will keep the kenc and khmac values in the list to use it after
    for i in range(5):
        U1= KS + u1 #concatenate KS and LeaveMeAlone. KS is used at the first iteration. Then, KS will become KKDFNEXT in line 141 to create the chain
        KENC = SHA3_256.new(U1).digest() 
        U2= KENC + u2
        KHMAC= SHA3_256.new(U2).digest()
        U3= KHMAC + u3
        KKDFNext= SHA3_256.new(U3).digest()
        print("this is for ",i+1,"th message:   kenc:",KENC, "khmac: ", KHMAC)
        print("this is KKDF next: ", KKDFNext)
        KS= KKDFNext #KS becomes KKDFNEXT
        list_of_keys.append([KENC, KHMAC])
        print("")
    return list_of_keys

#decrypt the message coming from the server
def decrypt(MES,KENC, KHMAC):
    MES = MES.to_bytes((MES.bit_length() + 7) // 8, 'big')
    print("Converted messages to byte to decrypt it: ", MES)
    MAC = MES[len(MES) - 32:]#seperate mac
    cipher = AES.new(KENC, AES.MODE_CTR, nonce=MES[0:8]) # take nonce as the first 8 bytes create aes object to decrypt
    dtext = cipher.decrypt(MES[8:len(MES) - 32]) #decrypt using AES128-CTR
    decmessage = dtext.decode()
    h = HMAC.new(KHMAC, digestmod=SHA256) #authentication is provided using HMAC-SHA256
    h.update(MES[8:len(MES) - 32])
    print("MAC value is: ", MAC)
    #we try to verify the mac value. If error occurs the code will go to except block
    try:
        h.verify(MAC)
        print("The message is authentic. Message:")
        h = decmessage
        print(decmessage)
        return decmessage #returns the decrypted message if mac value is valid
    except ValueError:
        print("The message is NOT!! authentic. Message:")
        h = decmessage
        print(decmessage)
        return ('INVALIDHMAC')#returns the INVALIDHMAC if mac value is not valid

def key_gen(curve): #key generation function.First it gets a random number as private key(sA) then we use this private key to generate public key QA(x,y)
    P = curve.generator
    ord = curve.order
    rand = random.randint(1, ord-1)
    sA = rand
    QA = sA * P
    return sA, QA

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

#functions for OTK creation
def generateHMAC(spk_x,spk_y,curve,spka_priv):#function to generate hmac keys
    QB = Point(spk_x, spk_y, curve)
    T = spka_priv * QB
    u = b'NoNeedToRideAndHide'
    U= T.x.to_bytes((T.x.bit_length()+7)//8, byteorder='big') + T.y.to_bytes((T.y.bit_length()+7)//8, byteorder='big') + u #concatenate x +y + u
    HMAC1 = SHA3_256.new(U).digest() #create SHA_256 instance
    print("")
    print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    return(HMAC1)

def Otk(HMAC1, q_a):
    x= q_a.x
    y=q_a.y
    message= x.to_bytes((x.bit_length()+7)//8, byteorder='big') + y.to_bytes((y.bit_length()+7)//8, byteorder='big') #concatenate x and y
    hashed = HMAC.new(HMAC1,message, digestmod=SHA256).hexdigest() #create HMAC instance with key, message and digestmod
    return hashed

def GenerateOTK(spk_x,spk_y,curve,spka_priv):
    HMAC=generateHMAC(spk_x,spk_y,curve,spka_priv) #generate key
    #create 11 keys to register
    list_of_priv=[] 
    for i in range(11):
        s_a, q_a= key_gen(curve) #create private and public key pairs 
        print(i,"th key "," Private part: ", s_a, " Public X : ", q_a.x, " Public Y : ", q_a.y)
        print(" ")
        list_of_priv.append(s_a)#keep private part in a list, when server returns an otk_id we will be easily getting the private part of that index
        hash=Otk(HMAC,q_a) #returns calculated hmac
        OTKReg(i,q_a.x,q_a.y,hash) #register the otk's
        print('********')
        print(" ")   
        print(list_of_priv)
    return list_of_priv

h_id=56365705298335195759583071608191261490605288257504072428239477159586215640934
s_id=72181175799194244208032321844652834437618900902501414399702671064129660880699
priv_id=57482405858864034497815686426091936426005352169501135761449175784315194678703
priv_spk=78581042307041991078283036230835254963694308522644962946554348182220004237272
print("Here is my private Identity Key: ", priv_id)
print("")
print("First we reset SPK and OTK in case they are registered, we want to start from begining:")
ResetSPK(h_id,s_id)
ResetOTK(h_id,s_id)
print("")
print("Generating SPK...")
spka_priv, spka_pub = key_gen(curve)
print("Private SPK: ", spka_priv)
print("Public SPK-X: ", spka_pub.x)
print("Public SPK-Y: ", spka_pub.y)
conca= spka_pub.x.to_bytes((spka_pub.x.bit_length()+7)//8, byteorder='big')+ spka_pub.y.to_bytes((spka_pub.y.bit_length()+7)//8, byteorder='big')
s,h =SignGen2(conca,curve,57482405858864034497815686426091936426005352169501135761449175784315194678703)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")
print("")
spk_x, spk_y, h, s = SPKReg(h,s,spka_pub.x,spka_pub.y)
print("if server verifies the signature it will send its SPK and corresponding signature. If this is the case SPKReg() function will return those")
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("Recreating the message(SPK) signed by the server. Verifying the server's SPK. If server's SPK is verified we can move to the OTK generation step")
print("Is SPK verified?:")
verify(h,s,spk_x,spk_y, curve, IKey_Ser)
print("Public key of the server:", spk_x," , " , spk_y)
print("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("")

""" 2.3 Registration of OTKs """
    #ReadMe
""" A hash-based MAC (HMAC) function is used to create HMAC keys.Then, we generate 10 one-time public and private keypairs. """
print("Creating OTK's: ")
otk_list_privates=GenerateOTK(spk_x,spk_y,curve,spka_priv)


print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("Telling pseudoclient to send me messages using PseudoSendMsg")
print("Signing my stuID with my private IK. h=",h_id," s=",s_id,"Server returns:")
PseudoSendMsg(h_id,s_id)


#request messages
mes1=ReqMsg(h_id,s_id)
mes2=ReqMsg(h_id,s_id)
mes3=ReqMsg(h_id,s_id)
mes4=ReqMsg(h_id,s_id)
mes5=ReqMsg(h_id,s_id)
print("")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

#take the message part of the server response
MES1 = mes1[3]
MES2 = mes2[3]
MES3 = mes3[3]
MES4 = mes4[3]
MES5 = mes5[3]
#take client id
client = mes1[0]
#take otk id
otk_id= mes1[1]

print("From client ", client, ": ")
print("1. message: ", MES1)
print("2. message: ", MES2)
print("3. message: ", MES3)
print("4. message: ", MES4)
print("5. message: ", MES5)
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#find otk private part from the list. otk_id  will give us the index of it
otk_priv=otk_list_privates[otk_id]
print("this is otk_priv:" ,otk_priv)
#take server public x and y to generate the point
server_x=mes1[4]
server_y=mes1[5]
ephemeralPub= Point(server_x, server_y,curve)
#generate KS from private part of the otk and ephemeral key
KS=generateKS(otk_priv,ephemeralPub)
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#generate the chain and get the array list from generateKDF function
list_of_keys=generateKDF(KS)
#get kenc for each of the messages
KENC1=list_of_keys[0][0]
KENC2=list_of_keys[1][0]
KENC3=list_of_keys[2][0]
KENC4=list_of_keys[3][0]
KENC5=list_of_keys[4][0]
#get kmac for each of the messages
KHMAC1= list_of_keys[0][1]
KHMAC2= list_of_keys[1][1]
KHMAC3= list_of_keys[2][1]
KHMAC4= list_of_keys[3][1]
KHMAC5= list_of_keys[4][1]
#decrypt messages using kenc and khmac
print("For 1. message:")
dec_mes1=decrypt(MES1,KENC1,KHMAC1)
print("")
print("For 2. message:")
dec_mes2=decrypt(MES2,KENC2,KHMAC2)
print("")
print("For 3. message:")
dec_mes3=decrypt(MES3,KENC3,KHMAC3)
print("")
print("For 4. message:")
dec_mes4=decrypt(MES4,KENC4,KHMAC4)
print("")
print("For 5. message:")
dec_mes5=decrypt(MES5,KENC5,KHMAC5)
print("")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

#SEND DECRPYPTED MESSAGES TO CHECKER FUNCTION
Checker(stuID, client, 1, dec_mes1)
Checker(stuID, client, 2, dec_mes2)
Checker(stuID, client, 3, dec_mes3)
Checker(stuID, client, 4, dec_mes4)
Checker(stuID, client, 5, dec_mes5)


