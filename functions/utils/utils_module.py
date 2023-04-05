from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
# from functions.rsa.rsa_module import *
from functions.aes.my_aes_module import *
from Crypto.Cipher import PKCS1_OAEP
from client_package.rsa.rsa_module import *


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
