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

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(stuid,keyID,x,y,hmac):
    mes = {'ID':stuid, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(stuId,h,s):
    mes = {'ID':stuId, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

def PseudoSendMsgPH3(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json = mes)		
    print(response.json())

def ReqMsg(stuId,h,s):
    mes = {'ID':stuId, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]
    
def SendMsg(idA, idB, otkid, msgid, msg, ekx, eky):
    mes = {"IDA":idA, "IDB":idB, "OTKID": int(otkid), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json = mes)
    print(response.json())    
        
def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json = OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']      
    else:
        return -1, 0, 0

def key_gen(curve): #key generation function.First it gets a random number as private key(sA) then we use this private key to generate public key QA(x,y)
    P = curve.generator
    ord = curve.order
    rand = random.randint(1, ord-1)
    sA = rand
    QA = sA * P
    return sA, QA

def Status(stuID, h, s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)	
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']	

def SignGen(m, curve, s_A): 
    n = curve.order
    P = curve.generator
    k = random.randint(1, n-2)   
    R = k * P    
    r = R.x % n  
    hx = SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+ m.to_bytes((m.bit_length()+7)//8, byteorder='big'))
    h = int.from_bytes(hx.digest(), byteorder='big') % n
    s = (k - s_A * h ) % n
    return s, h  

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

def GenerateOTK(stuid,spk_x,spk_y,curve,spka_priv):
    HMAC=generateHMAC(spk_x,spk_y,curve,spka_priv) #generate key
    #create 11 keys to register
    list_of_priv=[] 
    for i in range(11):
        s_a, q_a= key_gen(curve) #create private and public key pairs 
        print(i,"th key "," Private part: ", s_a, " Public X : ", q_a.x, " Public Y : ", q_a.y)
        print(" ")
        list_of_priv.append(s_a)#keep private part in a list, when server returns an otk_id we will be easily getting the private part of that index
        hash=Otk(HMAC,q_a) #returns calculated hmac
        OTKReg(stuid,i,q_a.x,q_a.y,hash) #register the otk's
        print('********')
        print(" ")   
    return list_of_priv

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

#function to create aes object in counter mode
def encrypt_aes(m, aes_key):
    nonce = Random.get_random_bytes(8) #create nonce with random 
    aes = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=nonce)
    c = aes.encrypt(m.encode())
    return nonce, c

#function to create hmac value
def generate_HMAC_SHA2_256(Kmac,m):
    sha = HMAC.new(Kmac, digestmod=SHA256)
    hash_val = sha.update(m)
    hash_val = hash_val.digest()
    return hash_val

#function to create the message in the form of nonce + cipher + mac
def sendMessages(message,KENC, KHMAC):
    nonce, c = encrypt_aes(message, KENC) #create aes object
    hmac = generate_HMAC_SHA2_256(KHMAC,c) 
    msg1 = nonce + c + hmac #message is formed
    msg1= int.from_bytes(msg1, byteorder='big')
    return msg1

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

h_id=56365705298335195759583071608191261490605288257504072428239477159586215640934
s_id=72181175799194244208032321844652834437618900902501414399702671064129660880699
priv_id=57482405858864034497815686426091936426005352169501135761449175784315194678703
print("Here is my private Identity Key: ", priv_id)
print("First we reset SPK and OTK in case they are registered, we want to start from begining:")
ResetSPK(h_id,s_id)
ResetOTK(25357,h_id,s_id)
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
otk_list_privates=GenerateOTK(25357,spk_x,spk_y,curve,spka_priv)
print("Checking status of the sender 25357: ")
print("")
Status(25357,h_id,s_id)

print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("")
print("I'll request messages from the pseudo client. It will send me 5 messages. But this time no invalid hmac")
print("Signing my stuID with my private IK. h=",h_id," s=",s_id,"Server returns:")
PseudoSendMsgPH3(h_id,s_id)
print(" ")
print("Checking status: ")
Status(25357,h_id,s_id)
print(" ")

#request messages
print("Requesting messages from server:")
print("")
mes1=ReqMsg(stuID,h_id,s_id)
print("")
mes2=ReqMsg(stuID,h_id,s_id)
print("")
mes3=ReqMsg(stuID,h_id,s_id)
print("")
mes4=ReqMsg(stuID,h_id,s_id)
print("")
mes5=ReqMsg(stuID,h_id,s_id)
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

print("Saving the collected plaintext: ")
print(dec_mes1)
print(dec_mes2)
print(dec_mes3)
print(dec_mes4)
print(dec_mes5)
print("")
print("Now I'll encrypt the messages I retrived initially from the server and send it to pseudo-client(18007) for auto-grading I'll send them in a SINGLE BLOCK. But ORDER of the messages should be considered")
print("Signing The stuIDB of party B with my private IK")
#sign the pseudo clients id with my private key
s_send_pseudo,h_send_pseudo = SignGen(18007,curve,priv_id)
#request otk info of the pseudo client
otk_info_pseudo=reqOTKB(25357,18007, h_send_pseudo, s_send_pseudo)
print("The other party's OTK public key is acquired from the server ...")
print(" ")
#extract otk info
key_id_ps=otk_info_pseudo[0]
otk_x_receiver_ps=otk_info_pseudo[1]
otk_y_receiver_ps=otk_info_pseudo[2]
print("Generating ephemeral key: ")
#generate ephemeral key with key_gen function
ephemeral_priv_ps, ephemeral_pub_ps=key_gen(curve)
print("Private part of my EK:", ephemeral_priv_ps)
print("")
pseudo=Point(otk_x_receiver_ps,otk_y_receiver_ps,curve)
print("Generating the KDF chain for the encryption and the MAC value generation")
print("Generating session key using my EK and pseudo clients's Public OTK/ Ph")
print("")
#generate KS and KDF
KS_ps=generateKS(ephemeral_priv_ps,pseudo)
#generate the chain and get the array list from generateKDF function
list_of_keys1=generateKDF(KS_ps)


#get kenc for each of the messages
KENC1ps=list_of_keys1[0][0]
KENC2ps=list_of_keys1[1][0]
KENC3ps=list_of_keys1[2][0]
KENC4ps=list_of_keys1[3][0]
KENC5ps=list_of_keys1[4][0]
#get kmac for each of the messages
KHMAC1ps= list_of_keys1[0][1]
KHMAC2ps= list_of_keys1[1][1]
KHMAC3ps= list_of_keys1[2][1]
KHMAC4ps= list_of_keys1[3][1]
KHMAC5ps= list_of_keys1[4][1]

print("Sending the message to the server, so it would deliver it to pseudo-client: ")
print("")
#sendMessages function will return the message that we will send as: nonce + cipher + MAC
message1ps=sendMessages(dec_mes1,KENC1ps,KHMAC1ps)
message2ps=sendMessages(dec_mes2,KENC2ps,KHMAC2ps)
message3ps=sendMessages(dec_mes3,KENC3ps,KHMAC3ps)
message4ps=sendMessages(dec_mes4,KENC4ps,KHMAC4ps)
message5ps=sendMessages(dec_mes5,KENC5ps,KHMAC5ps)

#send message to server with the formed messages
SendMsg(25357,18007,key_id_ps,1,message1ps,ephemeral_pub_ps.x,ephemeral_pub_ps.y)
print("")
SendMsg(25357,18007,key_id_ps,2,message2ps,ephemeral_pub_ps.x,ephemeral_pub_ps.y)
print("")
SendMsg(25357,18007,key_id_ps,3,message3ps,ephemeral_pub_ps.x,ephemeral_pub_ps.y)
print("")
SendMsg(25357,18007,key_id_ps,4,message4ps,ephemeral_pub_ps.x,ephemeral_pub_ps.y)
print("")
SendMsg(25357,18007,key_id_ps,5,message5ps,ephemeral_pub_ps.x,ephemeral_pub_ps.y)
print("")

print("Checking ststus of the sender 25357:")
Status(25357,h_id,s_id)
print("")
print("SENDING MESSAGES TO PSEODO-CLIENT IS OVER")


#Sending message to a friend
print("")
#list of messages to be sent
messages=["eylul is receiving messages", "deniz sent messages to eylul","happy new year", "cs411 is fun","see you next year"]
print("Now I want to send messages to my friend. Her id is 25320. Her name is Eylul and she is real :)")
print("Signing The stuIDB of party B with my private IK")
#sign the id of the friend with the private key
s_send_friend,h_send_friend = SignGen(25320,curve,priv_id)
print("Requesting party B's OTK ...")
#request otk information of the friend
otk_info_friend=reqOTKB(25357,25320, h_send_friend, s_send_friend)
#extract the response
key_id_friend=otk_info_friend[0]
otk_x_receiver_friend=otk_info_friend[1]
otk_y_receiver_friend=otk_info_friend[2]
print("The other party's OTK public key is acquired from the server ...")
print("")
print("Generating Ephemeral key")
print("Our 5 messages will be : ",messages)
#create ephemeral key
ephemeral_priv_friend, ephemeral_pub_friend=key_gen(curve)
#create point with public otk of our friend
point_friend=Point(otk_x_receiver_friend,otk_y_receiver_friend,curve)
print("Generating the KDF chain for the encryption and the MAC value generation")
print("")
print("Generating session key using my EK and my friends Public OTK/ Phase 3...")
KS_friend=generateKS(ephemeral_priv_friend,point_friend)
#generate the chain and get the array list from generateKDF function
list_of_keys_friend=generateKDF(KS_friend)


#get kenc for each of the messages
KENC1p=list_of_keys_friend[0][0]
KENC2p=list_of_keys_friend[1][0]
KENC3p=list_of_keys_friend[2][0]
KENC4p=list_of_keys_friend[3][0]
KENC5p=list_of_keys_friend[4][0]
#get kmac for each of the messages
KHMAC1p= list_of_keys_friend[0][1]
KHMAC2p= list_of_keys_friend[1][1]
KHMAC3p= list_of_keys_friend[2][1]
KHMAC4p= list_of_keys_friend[3][1]
KHMAC5p= list_of_keys_friend[4][1]


print("Encrypting the message with Kenc1 and created a mac value with Khmac1. Then created msg in this format: nonce+cipher+hmac. Converted to int to be able to send it")
print("")
#sendMessages function will return the message that we will send as: nonce + cipher + MAC
message1=sendMessages(messages[0],KENC1p,KHMAC1p)
message2=sendMessages(messages[1],KENC2p,KHMAC2p)
message3=sendMessages(messages[2],KENC3p,KHMAC3p)
message4=sendMessages(messages[3],KENC4p,KHMAC4p)
message5=sendMessages(messages[4],KENC5p,KHMAC5p)

#send the messages to server to deliver it to our friend
SendMsg(25357,25320,key_id_friend,1,message1,ephemeral_pub_friend.x,ephemeral_pub_friend.y)
print("")
SendMsg(25357,25320,key_id_friend,2,message2,ephemeral_pub_friend.x,ephemeral_pub_friend.y)
print("")
SendMsg(25357,25320,key_id_friend,3,message3,ephemeral_pub_friend.x,ephemeral_pub_friend.y)
print("")
SendMsg(25357,25320,key_id_friend,4,message4,ephemeral_pub_friend.x,ephemeral_pub_friend.y)
print("")
SendMsg(25357,25320,key_id_friend,5,message5,ephemeral_pub_friend.x,ephemeral_pub_friend.y)

#decrypt the messages sent to friend which is 25320 Eylul Onar to check
print("")
print("Checking status of my friend 25320: ")
Status(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
print("Now we will request the messages in the inbox of our friend to check if we send it correctly: ")
print("")

#request the messages
mes1_fr=ReqMsg(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
mes2_fr=ReqMsg(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
mes3_fr=ReqMsg(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
mes4_fr=ReqMsg(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
mes5_fr=ReqMsg(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
print("Checking status of my friend: ")
Status(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
#get the message parts
MES1_fr = mes1_fr[3]
MES2_fr = mes2_fr[3]
MES3_fr = mes3_fr[3]
MES4_fr = mes4_fr[3]
MES5_fr = mes5_fr[3]
#take client id
client_fr = mes1_fr[0]
#take otk id
otk_id_fr= mes1_fr[1]
print("")
print("From client 25357: ")
print("1. message: ", MES1_fr)
print("2. message: ", MES2_fr)
print("3. message: ", MES3_fr)
print("4. message: ", MES4_fr)
print("5. message: ", MES5_fr)
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

#find otk private part from the list. otk_id  will give us the index of it
otk_list_privates_eyl= [67679539769300658494589940669724000837783466556601731515627689520473424656601,53840714680340660408827157182283088098393897673709018465785791565414821565715,34747498323052266774683298869766303187708871727309674847427408161617785997364,19474333695998524147001075462145055507985090625081668286202664815137657579038,12717908355613760499339820837980647244074439283574955870602970962701229626545,90527706772828969160194748209997188267676391537902951544469727891203010835420,54116806745951589047059821151303861903732024380247589674167700950082108600985,107902834944767345307823768947074187163115917239987207936280245287922296707347,88621855982818959694552691304485230195746931105476680051513576692156418605118,50834749784856605020465498580805346321644995249686767693036407234323790395445]
otk_priv_fr=otk_list_privates_eyl[otk_id_fr]
print("this is otk_priv:" ,otk_priv_fr)
#take server public x and y to generate the point
server_x_fr=mes1_fr[4]
server_y_fr=mes1_fr[5]
ephemeralPub_fr= Point(server_x_fr, server_y_fr,curve)
#generate KS from private part of the otk and ephemeral key
KS_fr=generateKS(otk_priv_fr,ephemeralPub_fr)
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
#generate the chain and get the array list from generateKDF function
list_of_keys_fr=generateKDF(KS_fr)
#get kenc for each of the messages
KENC1_fr=list_of_keys_fr[0][0]
KENC2_fr=list_of_keys_fr[1][0]
KENC3_fr=list_of_keys_fr[2][0]
KENC4_fr=list_of_keys_fr[3][0]
KENC5_fr=list_of_keys_fr[4][0]
#get kmac for each of the messages
KHMAC1_fr= list_of_keys_fr[0][1]
KHMAC2_fr= list_of_keys_fr[1][1]
KHMAC3_fr= list_of_keys_fr[2][1]
KHMAC4_fr= list_of_keys_fr[3][1]
KHMAC5_fr= list_of_keys_fr[4][1]
#decrypt messages using kenc and khmac
print("For 1. message:")
dec_mes1_fr=decrypt(MES1_fr,KENC1_fr,KHMAC1_fr)
print("")
print("For 2. message:")
dec_mes2_fr=decrypt(MES2_fr,KENC2_fr,KHMAC2_fr)
print("")
print("For 3. message:")
dec_mes3_fr=decrypt(MES3_fr,KENC3_fr,KHMAC3_fr)
print("")
print("For 4. message:")
dec_mes4_fr=decrypt(MES4_fr,KENC4_fr,KHMAC4_fr)
print("")
print("For 5. message:")
dec_mes5_fr=decrypt(MES5_fr,KENC5_fr,KHMAC5_fr)
print("")
print("Checking status of the receiver friend 25320: ")
Status(25320,85295525610217237389744815823024300426826268595695770784410563183744900104420,15256267962537210273618505250061081659544033638529582358522766324487776169289)
print("")
print("Checking status of the sender 25357: ")
Status(25357,h_id,s_id)