from Crypto.PublicKey import RSA
import os
from Crypto.Cipher import PKCS1_OAEP


def gen_rsa_key():
    isExist = os.path.exists('client1/rsa/private.pem')
    if isExist:
        print('Key already exist')
        return True
    else:
        key_pair = RSA.generate(2048)

        # Export de la clé privée dans un fichier
        with open("client1/rsa/private.pem", "wb") as f:
            f.write(key_pair.export_key())

        # Export de la clé publique dans un fichier
        with open("client1/rsa/public.pem", "wb") as f:
            f.write(key_pair.publickey().export_key())

        return False


def load_rsa_keypair():
    try:
        # Import de la clé privée depuis le fichier
        with open("client1/rsa/private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        # Import de la clé publique depuis le fichier
        with open("client1/rsa/public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        return private_key, public_key

    except Exception as e:
        print('Error occurs when trying to load rsa keys: ', e)


def cipher_secret_key(public_key, secret_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(secret_key)

    return encrypted_key
