from functions.aes.my_aes_module import *
from functions.mqtt.mqtt_module import *
from functions.rsa.rsa_module import *
import base64

def send_message():
    message = input("Tapez votre texte: ")
    message_byte = message.encode('utf-8')
    recipient = input("Tapez votre destinataire: ")

    private_key, public_key = load_rsa_keypair()

    key = aes_gen_secret_key()

    encrypted_key = cipher_secret_key(public_key, key)

    ciphertext, cipher, key, tag = aes_cipher(key, message_byte)

    data = {
        'recipient': recipient,
        'key': base64.b64encode(encrypted_key).decode('utf-8'),
        'message': base64.b64encode(ciphertext).decode('utf-8')
    }
    client_publish(data)


if __name__ == '__main__':
    # gen_rsa_key()
    # private_key, public_key = load_rsa_keypair()
    send_message()
