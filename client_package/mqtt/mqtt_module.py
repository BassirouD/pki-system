import os
import paho.mqtt.client as paho
import sys
import json
from functions.utils.utils_module import *
from functions.certificat.srv.certif_server_module import *


def client_publish(data):
    try:
        client = paho.Client()
        client.connect('localhost', 5000)
        payload = json.dumps(data)
        client.publish('srv', payload)
        client.disconnect()
        print('Data published...!')
    except Exception as e:
        print('Error occurs when trying to publish data: ', e)


def on_message_client(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    data = msg.payload.decode()
    data_load = json.loads(data)
    recipient = data_load['recipient']
    key = data_load['key']
    message = data_load['message']
    plaintext = decrypt_key_decrypt_message(encrypted_key=key, encrypted_message=message)

    print('Message reçu : ', plaintext)


def on_message_client_caCertif(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post1/certificat/ca_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat CA enregistré dans ca_cert.pem")


def on_message_client_request_signkey(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def client_consumer():
    client = paho.Client()
    client.on_connect = on_client_connect
    client.on_message = on_message_client
    client.connect('localhost', 5000, 60)
    client.subscribe('srv')
    client.loop_forever()


def on_client_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("test/topic")


def request_sign_key(username):
    try:
        # Lecture de la clé publique à partir du fichier
        with open(f'{username}/rsa/public.pem', 'rb') as f:
            public_key = f.read()

        client = paho.Client()

        client.connect('localhost', 5000)

        message = {
            'public_key': public_key.decode('utf-8'),
            'client': username
        }

        payload = json.dumps(message)
        # Publication du message sur la file 'request_sign_key'
        client.publish('request_sign_key', payload)

        client.subscribe('signed_key' + username)

        client.on_connect = on_client_connect
        client.on_message = on_message_client_request_signkey

        # Déconnexion du client MQTT

        print('Request sign pubkey send successfully!')
        client.loop_forever()
    except Exception as e:
        print('Error of request sign pubkey', e)


def on_message_client_get_ca_certif(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def client_consumer_for_caCertif(username):
    print('here known')
    client = paho.Client()
    client.on_connect = on_client_connect
    client.on_message = on_message_client_caCertif
    client.connect('localhost', 5000, 60)
    client.subscribe('return_certif')
    client.loop_forever()


def client_get_ca_certif(username):
    client = paho.Client()
    client.connect('localhost', 5000)
    client.publish('get_certif', username)
    client_consumer_for_caCertif(username)
