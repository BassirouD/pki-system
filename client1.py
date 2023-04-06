import base64
from client_package.rsa.rsa_module import *
from client_package.mqtt.mqtt_module import *


def send_message():
    message = input("Tapez votre texte: ")
    message_byte = message.encode('utf-8')
    recipient = input("Tapez votre destinataire: ")

    private_key, public_key = load_rsa_keypair(recipient)

    key = aes_gen_secret_key()

    encrypted_key = cipher_secret_key(public_key, key)

    ciphertext, key = aes_cipher(key, message_byte)

    data = {
        'recipient': recipient,
        'key': base64.b64encode(encrypted_key).decode('utf-8'),
        'message': base64.b64encode(ciphertext).decode('utf-8')
    }
    client_publish(data)
    print(public_key)
    print(type(public_key))


if __name__ == '__main__':
    # gen_rsa_key('post1')
    # gen_key_client('post1')
    # print(result)

    # key, pkey = new_load_private_key('post1')
    # print(pkey)
    # request_sign_key('post1')
    # private_key, public_key = load_rsa_keypair()
    # send_message()

    #Envoie message
    client_get_pubkey_from_srv()

    # request_sign_key('post1')

    # client_get_ca_certif('post1')

    # client_shared_pubkey('post1')
