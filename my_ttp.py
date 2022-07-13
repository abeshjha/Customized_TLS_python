from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
import time

def create_CA():
    ca_key = crypto.PKey()                              
    ca_key.generate_key(crypto.TYPE_RSA, 2048)
    ca_cert = crypto.X509()
    ca_cert.set_version(2)                             

    ca_subj = crypto.X509Name(ca_cert.get_subject())
    ca_subj.__setattr__('C', "NP")
    ca_subj.__setattr__('ST', "Kathmandu")
    ca_subj.__setattr__('L', "Lalitpur")
    ca_subj.__setattr__('O', "Abesh CA")
    ca_subj.__setattr__('OU', "IITD")

    ca_cert.set_subject(ca_subj)
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(365*24*60*60)

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
    ])
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
    ])

    ca_cert.sign(ca_key, 'sha256')


    with open('ttp.crt', "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))
    with open('ttp_private.key', "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))
    with open('ttp_public.key', "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))


def create_cert(client_cn,path):

    with open("ttp.crt", "r") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    ca_subj = ca_cert.get_subject()

    with open("ttp_private.key", "r") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    with open(path, "r") as f:
        user_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

    client_cert = crypto.X509()
    client_cert.set_version(2)

    client_subj = client_cert.get_subject()
    client_subj.commonName = client_cn

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(user_key)
    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365*24*60*60)

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])

    client_cert.sign(ca_key, 'sha384')


    with open(client_cn + ".crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))

def main():
    print("--------Self Signed Certificate Created-------------")
    time.sleep(2)
    print("Generating func for signing server and client certificate....")
    time.sleep(2)
    print("Created!!")
    create_CA()
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(pem)
        

if __name__ == "__main__":
    main()
