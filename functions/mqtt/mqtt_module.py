import os
import paho.mqtt.client as paho
import sys
import json
from functions.utils.utils_module import *


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("test/topic")


def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def star_loop_mqtt_server(host):
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, 5000, 60)
    client.subscribe('srv')
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
    print(
        '*****************************************************************Gagné***********************************************************')
    print(plaintext)
    print(
        '*****************************************************************Gagné***********************************************************')


def client_consumer():
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message_client
    client.connect('localhost', 5000, 60)
    client.subscribe('srv')
    client.loop_forever()
