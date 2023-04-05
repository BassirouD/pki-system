import ssl
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from functions.mqtt.mqtt_module import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ---------------------------------------------------------
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


def gen_certification():
    try:
        # Génération de la clé privée
        # key = ssl.RSA.generate(2048)
        # Création d'un certificat auto-signé
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = 'FR'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)

        # Signer le certificat avec la clé privée
        cert.sign(key, 'sha256')

        # Stockage de la clé privée et du certificat dans des fichiers
        with open('functions/certificat/srv/certif/cert.pem', 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        with open('functions/certificat/srv/certif/key.pem', 'wb') as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        print('Generation certif done...')
    except Exception as e:
        print('Exception-->: ', e)


def load_cert_and_privkey():
    # Charger la clé privée et le certificat
    with open('functions/certificat/srv/certif/key.pem', 'rb') as key_file:
        key = key_file.read()
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)

    with open('functions/certificat/srv/certif/cert.pem', 'rb') as cert_file:
        cert = cert_file.read()
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    return key, pkey, cert, x509


def sign_pubkey(pubkey, username):
    try:
        key, pkey, cert, x509 = load_cert_and_privkey()
        print('key---------------->: ', key)
        print('pkey---------------->: ', pkey)
        print('cert---------------->: ', cert)
        print('x509---------------->: ', x509)
        # Créer une demande de signature
        req = crypto.X509Req()

        req.get_subject().CN = username  # Nom commun
        pubkey_obj = crypto.load_publickey(crypto.FILETYPE_PEM, pubkey)
        print(pubkey_obj)
        print(type(pubkey_obj))
        req.set_pubkey(pubkey_obj)
        req.sign(pkey, 'sha256')
        print('suite4')
        with open(f'{username}/rsa/certs/signed_cert.pem', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, req))

        print('req---------------->: ', req)

        data = crypto.dump_certificate(crypto.FILETYPE_PEM, req)
        # print('data---------------->: ', data)
        # publish_sign_pubkey(data, username)

        print('Sign pubkey done....')
    except Exception as e:
        print('Exception occurs when trying sign key: ', e)


# --------------------------------------------------new approch*-----------------------------------------------------**

def new_gen_certification():
    # Générer une clé RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Générer une clé ECDSA
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1()
    )

    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Créer un certificat auto-signé pour la CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"IDF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA Root"),
    ])

    issuer_serial_number = x509.random_serial_number()

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        issuer_serial_number
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False
        ),
        critical=True
    ).sign(private_key, algorithm=hashes.SHA256())

    # Sérialiser la clé privée au format PEM
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Sérialiser le certificat au format PEM
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)

    with open('functions/certificat/srv/certif/ca_public_key.pem', 'wb') as f:
        f.write(pem_public_key)

    # Écrire la clé privée dans un fichier
    with open('functions/certificat/srv/certif/ca_private_key.pem', 'wb') as f:
        f.write(pem_private_key)

    # Écrire le certificat dans un fichier
    with open('functions/certificat/srv/certif/ca_cert.pem', 'wb') as f:
        f.write(pem_cert)


def load_ca_certif():
    # Écrire le certificat dans un fichier
    with open('functions/certificat/srv/certif/ca_cert.pem', 'rb') as f:
        ca_certif = f.read()

    return ca_certif


def load_pubkey_by_username(username):
    # Écrire le certificat dans un fichier
    with open(f'{username}/rsa/public.pem', 'rb') as f:
        pubkey = f.read()

    return pubkey


def srv_save_client_pubkey(pubkey, username):
    # Écrire le certificat dans un fichier
    with open(f'functions/certificat/srv/client_pubkey/{username}_public.pem', 'wb') as f:
        f.write(pubkey)
        print(f"Public key for {username} saved successfully.")

    return True
