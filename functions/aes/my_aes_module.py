from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
import os

IV = b'MonIVSecretSecret'
KEY = get_random_bytes(16)
CIPHER = AES.new(KEY, AES.MODE_EAX, IV)


def aes_gen_secret_key():
    global KEY
    # Générer une clé secrète de 16 bytes (128 bits)
    key = KEY
    print('*********************************')
    print('result genkey aes: ', key)
    print('result genkey aes type: ', type(key))
    return key


def aes_cipher(key, message):
    global KEY
    global CIPHER
    # Chiffrement du message
    # cipher = AES.new(key, AES.MODE_EAX)
    ciphertext = CIPHER.encrypt(message)

    # Affichage du message chiffré
    print("Message chiffré:", ciphertext)
    return ciphertext, key


def aes_decrypt(ciphertext, cipher, key, tag):
    global CIPHER
    # Déchiffrement du message
    cipher = AES.new(key, AES.MODE_EAX, nonce=IV)
    plaintext = cipher.decrypt(ciphertext)

    # Vérification de l'intégrité du message
    try:
        # cipher.verify(tag)
        print("Message déchiffré>", plaintext.decode())
        return plaintext.decode()
    except ValueError:
        print("Le message est altéré ou invalide.")


def aes_decrypt2(key, ciphertext):
    print("Message chiffré> ", ciphertext)
    # Déchiffrement du message
    cipher = AES.new(key, AES.MODE_EAX, nonce=IV)
    plaintext = cipher.decrypt(ciphertext)

    # Vérification de l'intégrité du message
    try:
        # print("Message déchiffré> ", plaintext.decode())
        return plaintext.decode()
    except ValueError:
        print("Le message est altéré ou invalide.")
