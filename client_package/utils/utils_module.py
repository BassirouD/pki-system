from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from functions.rsa.rsa_module import *
from functions.aes.my_aes_module import *
from Crypto.Cipher import PKCS1_OAEP

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


# def decrypt_key_decrypt_message(encrypted_key, encrypted_message):
#     encrypted_key = b64decode(encrypted_key)
#     encrypted_message = b64decode(encrypted_message)
#
#     private_key, public_key = load_rsa_keypair()
#
#     cipher = PKCS1_OAEP.new(private_key)
#     decrypted_key = cipher.decrypt(encrypted_key)
#     # aes_key = private_key.decrypt(encrypted_key)
#
#     # decrypted_message = decrypt_f(encrypted_message, aes_key)
#
#     plaintext = aes_decrypt2(key=decrypted_key, ciphertext=encrypted_message)
#     return plaintext


def decrypt_key_decrypt_message(encrypted_key, encrypted_message, recipient):
    encrypted_key = b64decode(encrypted_key)
    encrypted_message = b64decode(encrypted_message)

    private_key, public_key = load_rsa_keypair(recipient)

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher.decrypt(encrypted_key)
    # aes_key = private_key.decrypt(encrypted_key)

    # decrypted_message = decrypt_f(encrypted_message, aes_key)

    plaintext = aes_decrypt2(key=decrypted_key, ciphertext=encrypted_message)
    return plaintext


def extract_pubkey_form_certif(certif):
    certif = x509.load_pem_x509_certificate(certif)
    pub_key = certif.public_key()

    return pub_key


def load_and_extract_ca_pubkey(client):
    with open(f'{client}/certificat/ca_cert.pem', 'rb') as f:
        ca_public_key_data = f.read()

    ca_cert = x509.load_pem_x509_certificate(ca_public_key_data)
    ca_pub_key = ca_cert.public_key()
    print('///////////////ca_pub_key///////////////////////')
    print(ca_pub_key)
    print('///////////////ca_pub_key///////////////////////')
    return ca_pub_key


def extract_signature(client_cert_data):
    client_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())
    signature = client_cert.signature
    print('///////////////signature///////////////////////')
    print(signature)
    print(type(signature))
    print('///////////////signature///////////////////////')

    return signature


def verify_signature(ca_pub_key, signature, client_public_key):
    # client_public_key_bytes = client_public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    client_public_key_bytes = client_public_key.export_key(format='DER')

    try:
        ca_pub_key.verify(
            signature,
            client_public_key_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature du certificat valide")
        return True
    except Exception as e:
        print("Signature du certificat invalide: ", e)
        return False
