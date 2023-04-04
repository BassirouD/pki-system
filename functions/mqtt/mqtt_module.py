import os
import paho.mqtt.client as paho
import sys
import json
from functions.utils.utils_module import *
from functions.certificat.srv.certif_server_module import sign_pubkey


def check_topic(topic, data):
    data_load = json.loads(data)
    if topic == 'request_sign_key':
        public_key = data_load['public_key']
        username = data_load['client']
        sign_pubkey(public_key, username)


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("test/topic")


def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    print('topic------>: ', msg.topic)
    print('topic type------>: ', type(msg.topic))
    my_topic = msg.topic
    data = msg.payload.decode()
    check_topic(my_topic, data)


def star_loop_mqtt_server(host):
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, 5000, 60)
    client.subscribe('srv')
    client.subscribe('request_sign_key')
    client.loop_forever()


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
    # print(msg.topic + " " + str(msg.payload))
    data = msg.payload.decode()
    data_load = json.loads(data)
    recipient = data_load['recipient']
    key = data_load['key']
    message = data_load['message']
    plaintext = decrypt_key_decrypt_message(encrypted_key=key, encrypted_message=message)

    print('Message reçu : ', plaintext)


def on_message_client_request_signkey(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))



def client_consumer():
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message_client
    client.connect('localhost', 5000, 60)
    client.subscribe('srv')
    client.loop_forever()


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

        client.on_connect = on_connect
        client.on_message = on_message_client_request_signkey

        # Déconnexion du client MQTT

        print('Request sign pubkey send successfully!')
        client.loop_forever()
    except Exception as e:
        print('Error of request sign pubkey', e)


def publish_sign_pubkey(data, mqtt_file):
    print('dans publish')
    client = paho.Client()
    client.connect('localhost', 5000, 60)
    client.publish('signed_key' + mqtt_file, data)
    client.disconnect()
