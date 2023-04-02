from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding


def aes_gen_secret_key():
    # Générer une clé secrète de 16 bytes (128 bits)
    key = get_random_bytes(16)
    print('*********************************')
    print('result genkey aes: ', key)
    return key


def aes_cipher(key, message):
    # Chiffrement du message
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    # Affichage du message chiffré
    print("Message chiffré:", ciphertext)
    return ciphertext, cipher, key, tag


def aes_decrypt(ciphertext, cipher, key, tag):
    # Déchiffrement du message
    cipher = AES.new(key, AES.MODE_EAX, cipher.nonce)
    plaintext = cipher.decrypt(ciphertext)

    # Vérification de l'intégrité du message
    try:
        cipher.verify(tag)
        print("Message déchiffré:", plaintext.decode())
        return plaintext.decode()
    except ValueError:
        print("Le message est altéré ou invalide.")
