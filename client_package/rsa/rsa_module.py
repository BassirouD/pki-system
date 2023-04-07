from Crypto.PublicKey import RSA
import os
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.x509.oid import NameOID
import datetime
from OpenSSL import crypto
from client_package.mqtt.mqtt_module import *


def gen_rsa_key(client):
    isExist = os.path.exists(f'{client}/rsa/private.pem')
    if isExist:
        print('Key already exist')
        return True
    else:
        key_pair = RSA.generate(2048)

        # Export de la clé privée dans un fichier
        with open(f"{client}/rsa/private.pem", "wb") as f:
            f.write(key_pair.export_key())

        # Export de la clé publique dans un fichier
        with open(f"{client}/rsa/public.pem", "wb") as f:
            f.write(key_pair.publickey().export_key())

        return False


def new_gen_rsa_key(client):
    isExist = os.path.exists(f'{client}/rsa/private.pem')
    if isExist:
        print('Key already exist')
        return True
    else:
        key_pair = RSA.generate(2048)

        # Export de la clé privée dans un fichier
        with open(f"{client}/rsa/private.pem", "wb") as f:
            f.write(key_pair.export_key())

        # Export de la clé publique dans un fichier
        with open(f"{client}/rsa/public.pem", "wb") as f:
            f.write(key_pair.publickey().export_key())

        return False


def load_rsa_keypair(post):
    try:
        # Import de la clé privée depuis le fichier
        with open(f"{post}/rsa/private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        # Import de la clé publique depuis le fichier
        with open(f"{post}/rsa/public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        return private_key, public_key

    except Exception as e:
        print('Error occurs when trying to load rsa keys: ', e)


def cipher_secret_key(public_key, secret_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(secret_key)
    print('encrypted_key---', encrypted_key)
    return encrypted_key


# def cipher_secret_key2(public_key, secret_key):
#     encrypted_key = public_key.encrypt(
#         secret_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return encrypted_key


# ---------------------------------------------New approach------------------------------------------------------------


def gen_key_client(username):
    # Générer une paire de clés RSA avec une longueur de 2048 bits
    is_keypair_exist = os.path.exists(f'{username}/rsa/private_key.pem')
    if is_keypair_exist:
        key, private_key = new_load_private_key(username)

    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Afficher les clés

        priv_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(f'{username}/rsa/private_key.pem', 'wb') as f:
            f.write(priv_key)

        with open(f'{username}/rsa/public_key.pem', 'wb') as f:
            f.write(pub_key)

    csr_serialization = create_demande_certif(private_key, username)

    request_certif(csr_serialization, username)

    return csr_serialization


def create_demande_certif(private_key, username):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Exemple" + username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"client@example." + username),
    ])
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    csr = builder.sign(private_key, hashes.SHA256())

    csr_serialization = csr.public_bytes(serialization.Encoding.PEM)

    return csr_serialization


def new_load_private_key(username):
    with open(f'{username}/rsa/private_key.pem', 'rb') as key_file:
        key = key_file.read()
    pkey = serialization.load_pem_private_key(key, password=None)

    return key, pkey
