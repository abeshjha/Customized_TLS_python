import hashlib
import hmac
import socket
import my_ttp
import ssl
import hmac
import random
import time
from _thread import * 
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

message_to_deliver = "The OTP for transferring Rs 1,00,000 to your friend’s account is 256345."
#Generating public and private keys at the server

def generate_server_keys():
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA,2048)
    with open('server_public.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
    with open('server_private.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
    
generate_server_keys()

def record_protocol_authenticate(plaintext,key,algo):
    signature = hmac.new(key, plaintext.encode(), algo).digest()
    message = str(signature) + "\n" + plaintext
    return message

def record_protocol_verify(ciphertext,key,algo):
    receivedtext = ciphertext.split("\n")
    print(receivedtext)
    signature = receivedtext[0]
    plaintext = receivedtext[1]
    obtained_signature = hmac.new(key, plaintext.encode(), algo).digest()
 
    if(signature == str(obtained_signature)):
        print("true")
        return True
    else:
        print("false")
        return False

def decrypt_key(ciphertext):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    original_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return original_message
    
    return data

my_ttp.create_cert("server", "server_public.key")

HOST = '127.0.0.1'
PORT_S = 1024
serv_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv_client_sock.bind((HOST,PORT_S))
serv_client_sock.listen()
print ("Server is up and listening")  
c,addr=serv_client_sock.accept()
print (addr[0] + " connected")
print("--------Handshake Start------\n\n")
time.sleep(2)
## Secure socket
client_socket = ssl.wrap_socket(c,server_side=True,cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLSv1_2,ca_certs="ttp.crt",certfile="server.crt",keyfile="server_private.key")
# Get certificate from the client

def verify_certificate():
    client_cert = client_socket.getpeercert()
    subject    = dict(item[0] for item in client_cert['subject'])
    issuer    = dict(item[0] for item in client_cert['issuer'])
    

    commonName = subject['commonName']
    issuer = issuer['countryName']
    version = client_cert['version']
    print("common name: " + commonName)
    print("issuer country: " + issuer)
    print("version: " + str(version))

    if(commonName == "client" and issuer == "NP" and version == 3):
        return True
    else:
        return False


while True:
   
    client_hello = client_socket.recv(1024).decode()
    print(client_hello)
    if("hello" in client_hello):
        print("--------Client hello recieved------\n\n")
        time.sleep(2)
        print("Verifying Client Certificate.....")
        result = verify_certificate()
        if result:
            time.sleep(2)
            print("--------Client certificate verification sucess!!------\n\n")
            print("Sending Serevr Hello Message.....")
            time.sleep(2)
            ran_int = random.randint(100000,900000)
            client_hello = "message: hello \n cipher_suit:ECDHE-RSA-AES128-SHA256 \n random_byte:"+str(ran_int)
            client_socket.send(client_hello.encode())
            
            encrypted_symmetric_key = client_socket.recv(1024)
            symmetric_key = decrypt_key(encrypted_symmetric_key)
            time.sleep(2)
            print("--------Authenticated Symmetric Key exchanged!!------\n\n")
            print("Securely sending messege.....")
            time.sleep(2)
            a = record_protocol_authenticate(message_to_deliver,symmetric_key,hashlib.sha256)
            client_socket.send(a.encode())


        else:
            print("--------Client certificate verification failed!!------\n\n")
            client_socket.close()
            
       
client_socket.close()

        

