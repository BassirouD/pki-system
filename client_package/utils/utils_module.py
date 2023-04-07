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
