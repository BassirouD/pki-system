import os
import paho.mqtt.client as paho
import sys


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("test/topic")


def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def star_loop_mqtt_server():
    client = paho.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect("broker.server.com", 6000, 60)
    client.loop_forever()
