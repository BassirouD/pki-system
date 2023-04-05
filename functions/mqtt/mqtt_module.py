import os
import paho.mqtt.client as paho
import sys
import json
from functions.utils.utils_module import *
from functions.certificat.srv.certif_server_module import *
import base64


def send_ca_certif(data):
    ca_certif = load_ca_certif()

    # payload = {
    #     'payload': payload.b64encode(encrypted_key).decode('utf-8'),
    #     'username': data
    # }

    client = paho.Client()
    client.connect('localhost', 5000)
    client.publish('return_certif', ca_certif)
    client.disconnect()


def check_topic(topic, data):
    if topic == 'request_sign_key':
        data_load = json.loads(data)
        public_key = data_load['public_key']
        username = data_load['client']
        sign_pubkey(public_key, username)

    if topic == 'get_certif':
        send_ca_certif(data)


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("test/topic")


def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    print('topic------>: ', msg.topic)
    print('topic type------>: ', type(msg.topic))
    my_topic = msg.topic
    data = msg.payload.decode()
    print('**********************************')
    print(data)
    print(type(data))
    print('**********************************')
    check_topic(my_topic, data)


def star_loop_mqtt_server(host):
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, 5000, 60)
    client.subscribe('srv')
    client.subscribe('request_sign_key')
    client.subscribe('get_certif')
    client.loop_forever()
