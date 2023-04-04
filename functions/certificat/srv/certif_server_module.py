import ssl
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from functions.mqtt.mqtt_module import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


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
