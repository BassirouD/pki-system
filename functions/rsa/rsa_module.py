from Crypto.PublicKey import RSA
import os
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


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


def load_rsa_keypair2(post):
    try:
        # Import de la clé privée depuis le fichier
        with open(f"{post}/rsa/private_key.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        # Import de la clé publique depuis le fichier
        with open(f"{post}/rsa/public_key.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        return private_key, public_key

    except Exception as e:
        print('Error occurs when trying to load rsa keys: ', e)


def cipher_secret_key(public_key, secret_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(secret_key)

    return encrypted_key


def cipher_secret_key2(public_key, secret_key):
    encrypted_key = public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def decypt_secret_key2(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_key
