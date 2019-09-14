# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5
import base64
# from Crypto import Random
# from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa ,padding
from cryptography.hazmat.primitives import serialization ,hashes

private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
public_key = private_key.public_key()

print(private_key)
print(public_key)

pemPrivate = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

   

# sender side *************************************************************
# get this from server before sending message
pemPublic = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) 
print("pem pub/lic",pemPublic)

pk = serialization.load_pem_public_key(pemPublic,backend=default_backend())

messageStr = "message needs to send message needs to send message needs to send message needs to send message needs to send message needs to send message needs to send message needs to sen" 
message = messageStr.encode()
# print(message.__sizeof__())
# print(messageStr.__sizeof__())
print(len(messageStr.encode('utf-8')))
# print(jg.__sizeof__())
ciphertext = pk.encrypt(
                message,
                padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
            )
signature = private_key.sign(
                    ciphertext,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA1()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA1()
                )
# print("cipher text ")
# print(ciphertext)
# print(len(ciphertext))
# print("signature")
# print(signature)
# print(len(signature))
# print("pem")
# print(pemPublic)
# print(len(pemPublic))
# sending message :: 
username = 'bob'
recvr_name = 'alice'
print("cipherText \n",ciphertext)
conCipher = base64.b64encode(ciphertext)
sendMsg = bytes("SEND " + recvr_name + "\nContent-length: " + str(len(ciphertext)) + "\n\n",'UTF-8') + conCipher
print( "sendmsg \n",sendMsg)
b64sendMsg = base64.b64encode(sendMsg)
print("b64EncodeSend Msg \n",b64sendMsg)
b64decodeSendMsg = base64.b64decode(b64sendMsg)
print("b64decodeSend msg \n",b64decodeSendMsg)
# msg = b64decodeSendMsg
msg = b64decodeSendMsg.decode()
msgrpart = msg.split('\n',3)
print(msgrpart[0])
print(msgrpart[1])
print(msgrpart[2])
print(msgrpart[3])
rct = base64.b64decode(msgrpart[3].encode())
print(rct)

# register 
# username = 'kailash'
# regMsg = bytes("REGISTER TORECV " + username + "\n\n",'UTF-8') + pemPublic
# b64registerMsg = base64.b64encode(regMsg)
# print("b64registerMsg")
# print(b64registerMsg)
# b64decodeRegMsg = base64.b64decode(b64registerMsg)
# print("b64decode msg")
# print(b64decodeRegMsg)
# msg = b64decodeRegMsg.decode()
# print(msg)
# i = 0
# for c in msg:
#     if c == '-':
#         break
#     i += 1
# msg1 = msg[:i]
# print(msg1)
# msg2 = msg[i:]
# print(msg2)


# (ciphertext,signature) -> server -> reciver
# reciver side *************************************************************
# get sender public key from server by same manner
spk = serialization.load_pem_public_key(pemPublic,backend=default_backend())
spk.verify( 
        signature,
        ciphertext,
        padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA1()
    )

plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
            )

print(plaintext.decode())