import hashlib
import hmac
import socket
import my_ttp
import ssl
import hmac
import random
import time
from _thread import * 
import os
import my_ttp
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generate_client_keys():
    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA,2048)
    with open("client_public.key", "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))
    with open("client_private.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))


generate_client_keys()
my_ttp.create_cert("client", "client_public.key")

def record_protocol_authenticate(plaintext,key,algo):
    signature = hmac.new(key, plaintext.encode(), algo).digest()
    message = str(signature) + "\n" + plaintext
    print(message)
    return message

def record_protocol_verify(ciphertext,key,algo):
    receivedtext = ciphertext.split("\n")
    print(receivedtext)
    signature = receivedtext[0]
  
    plaintext = receivedtext[1]
    print(plaintext)
    obtained_signature = hmac.new(key, plaintext.encode(), algo).digest()
 
    if(signature == str(obtained_signature)):
        return plaintext
    else:
        return "fail"

def verify_certificate():
    client_cert = secure_server_Socket.getpeercert()
    subject    = dict(item[0] for item in client_cert['subject'])
    issuer    = dict(item[0] for item in client_cert['issuer'])
    

    commonName = subject['commonName']
    issuer = issuer['countryName']
    version = client_cert['version']
    print("common name: " + commonName)
    print("issuer country: " + issuer)
    print("version: " + str(version))

    if(commonName == "server" and issuer == "NP" and version == 3):
        return True
    else:
        return False

def rsa_encryption(plaintext):
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    encrypted = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )
    return encrypted


context = ssl.SSLContext();
context.verify_mode = ssl.CERT_REQUIRED;

context.load_verify_locations("ttp.crt");

context.load_cert_chain(certfile="client.crt", keyfile="client_private.key");
HOST = '127.0.0.1'
PORT_S = 1024

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secure_server_Socket  = context.wrap_socket(server_socket);
secure_server_Socket.connect((HOST,PORT_S))
server_cert = secure_server_Socket.getpeercert();


ran_int = random.randint(100000,900000)
client_hello = "message: hello \n tls_version:ssl.PROTOCOL_TLSv1_2 \n cipher_suit:ECDHE-RSA-AES128-SHA256 \n hash_func: hashlib.sha256 \n random_byte:"+str(ran_int)
secure_server_Socket.send(client_hello.encode())

while True:
    server_hello = secure_server_Socket.recv(1024).decode()
    print(server_hello)   
    if("hello" in server_hello):
        print("--------Server hello recieved------\n\n")
    time.sleep(2)
    print("Verifying Server Certificate.....")
    result = verify_certificate()
    if result:
        time.sleep(2)
        print("--------Server certificate verification sucess!!------\n\n")
        print("Sending authenticated symmetric key for encryptiom.....")
        symmetric_key = os.urandom(16)

        encoded_symmetric_key = rsa_encryption(symmetric_key)
        secure_server_Socket.send(encoded_symmetric_key)
        final_message = secure_server_Socket.recv(1024).decode()
        time.sleep(2)
        print("------------Secure Message Recieved--------------\n\n")
        print(final_message)
        print("\n\nVerifying Message.....")
        time.sleep(2)
        m = record_protocol_verify(final_message,symmetric_key,hashlib.sha256)
        if (m!= "fail"):
            print("Verification Success. Final message is: \n")
            print(m)
        else:
            print("Verification failed!!")


    else:
        print("--------Client certificate verification failed!!------\n\n")
        secure_server_Socket.close()

