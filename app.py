from functions.aes.my_aes_module import *

if __name__ == '__main__':
    message = input("Tapez votre texte: ")
    message_byte = message.encode('utf-8')

    key = aes_gen_secret_key()

    ciphertext, cipher, key, tag = aes_cipher(key, message_byte)

    aes_decrypt(ciphertext, cipher, key, tag)

