import os
import paho.mqtt.client as paho
import sys
import json
from functions.utils.utils_module import *
from functions.certificat.srv.certif_server_module import *
from client_package.utils.utils_module import *
from client_package.rsa.rsa_module import *
import base64
import time
# from client_package.rsa.rsa_module import *
from Crypto.PublicKey import RSA
from functions.rsa.rsa_module import *
import threading
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

client_get_pubkey = paho.Client('get_pubkey_username')
client_get_certif = paho.Client('get_certif_username')
client_get_CA_certif = paho.Client('get_certif')


def on_message_client_caCertifA(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    # print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post1/certificat/ca_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat CA enregistré dans ca_cert.pem pour le post1")


def on_message_client_caCertifB(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    # print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post2/certificat/ca_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat CA enregistré dans ca_cert.pem pour le post2")


def on_message_client_caCertifC(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    # print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post3/certificat/ca_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat CA enregistré dans ca_cert.pem pour le post3")


def client_publish(data):
    client = paho.Client()
    client.connect('localhost', 5000)
    try:

        payload = json.dumps(data)
        client.publish('messages', payload)
        client.disconnect()
        print('Data published...!')
    except Exception as e:
        client.disconnect()
        print('Error occurs when trying to publish data: ', e)


def on_message_client(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    data = msg.payload.decode()
    data_load = json.loads(data)
    recipient = data_load['recipient']
    print('----------------------------------------------recipient:>', recipient)
    source = data_load['source']
    key = data_load['key']
    message = data_load['message']
    plaintext = decrypt_key_decrypt_message(encrypted_key=key, encrypted_message=message, recipient=recipient)

    print('############################################################################"')
    print('Source:> ', source, ' :----: ', 'Message reçu:> ', plaintext)
    print('############################################################################"')


def on_message_client2(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    data = msg.payload.decode()
    data_load = json.loads(data)
    recipient = data_load['recipient']
    # print('----------------------------------------------recipient:>', recipient)
    source = data_load['source']
    key = data_load['key']
    message = data_load['message']
    plaintext = decrypt_key_decrypt_message2(encrypted_key=key, encrypted_message=message, recipient=recipient)

    print('############################################################################"')
    print('Source:> ', source, ' :----: ', 'Message reçu:> ', plaintext)
    print('############################################################################"')


def on_message_client_caCertif(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post3/certificat/ca_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat CA enregistré dans ca_cert.pem")


def on_message_client_request_signkey(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def client_consumer(post):
    client = paho.Client()
    client.on_connect = on_client_connect
    client.on_message = on_message_client
    client.connect('localhost', 5000, 60)
    client.subscribe('canal_' + post)
    client.loop_forever()


def client_consumer2(post):
    client = paho.Client()
    client.on_connect = on_client_connect2
    client.on_message = on_message_client2
    client.connect('localhost', 5000, 60)
    client.subscribe('canal_' + post)
    client.loop_forever()


def on_client_connect(client, userdata, flags, rc):
    print("Wainting messages... ")
    # client.subscribe("test/topic")


def on_client_connect2(client, userdata, flags, rc):
    print("Wainting messages... ")
    # client.subscribe("test/topic")


def on_client_connect_ca_certif(client, userdata, flags, rc):
    print("Wainting CA certif... ")
    # client.disconnect()


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
    client = paho.Client()
    client.on_connect = on_client_connect_ca_certif
    if username == 'post1':
        client.on_message = on_message_client_caCertifA
    if username == 'post2':
        client.on_message = on_message_client_caCertifB
    if username == 'post3':
        client.on_message = on_message_client_caCertifC
    client.connect('localhost', 5000, 60)
    client.subscribe('return_certif')
    loop_thread = threading.Thread(target=client.loop_forever)
    loop_thread.start()
    time.sleep(1)
    # Stop the thread
    client.disconnect()
    client.loop_stop()

    # client.loop_forever(5)


def client_get_ca_certif(username):
    client = paho.Client()
    client.connect('localhost', 5000)
    client.publish('get_certif', username)
    client.disconnect()
    client_consumer_for_caCertif(username)


def client_shared_pubkey(username):
    try:
        client = paho.Client()
        client.connect('localhost', 5000)
        pubkey = load_pubkey_by_username(username)
        payload = {
            'pubkey': base64.b64encode(pubkey).decode('utf-8'),
            'username': username
        }
        client.publish('shared_client_pubkey', json.dumps(payload))
        client.disconnect()
        print('Pubkey shared successfully')
    except Exception as e:
        print('Error occurs when trying shared pub client key: ', e)


def on_client_connect_for_client_pubkey(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    time.sleep(5)
    client.disconnect()


def client_consumer_for_client_pubkey(username):
    # client = paho.Client()
    client_get_pubkey.on_message = on_message_client_pubkey
    # client.on_connect = on_client_connect_for_client_pubkey
    client_get_pubkey.connect('localhost', 5000, 60)
    client_get_pubkey.subscribe('return_pubkey')
    client_get_pubkey.loop_forever()


def client_consumer_for_client_certif(username):
    # client = paho.Client()
    client_get_certif.on_message = on_message_client_certif
    # client.on_connect = on_client_connect_for_client_pubkey
    client_get_certif.connect('localhost', 5000, 60)
    client_get_certif.subscribe('return_client_certif')
    client_get_certif.loop_forever()


def on_message_client_pubkey(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    # print(type(msg.payload.decode()))
    data_load = json.loads(msg.payload.decode())
    username = data_load['username']
    pubkey_b64 = data_load['pubkey']

    public_key = RSA.import_key(pubkey_b64)
    client_get_pubkey.disconnect()
    send_message_from_mqtt(public_key, username)


def on_message_client_certif(client, userdata, msg):
    # print(msg.topic + " " + str(msg.payload))
    data_load = json.loads(msg.payload.decode())
    username = data_load['username']
    certif = data_load['certif'].encode('utf-8')
    # certif = msg.payload
    pubkey = extract_pubkey_form_certif(certif)
    public_key_bytes = pubkey.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pycrypto = RSA.import_key(public_key_bytes)
    client_get_certif.disconnect()
    # ***********************************************************Verify signature***************************************
    # signature = extract_signature(certif)
    send_message_from_mqtt_certif(public_key_pycrypto, username)


def client_get_pubkey_from_srv():
    # client = paho.Client()
    recipient = ''
    while recipient != 'post1' and recipient != 'post2' and recipient != 'post3':
        recipient = input("Tapez votre destinataire:> ")
    client_get_pubkey.connect('localhost', 5000)
    client_get_pubkey.publish('get_pubkey_username', recipient)
    client_consumer_for_client_pubkey(recipient)


def client_get_certif_client_from_srv():
    recipient = input("Tapez votre destinataire:> ")
    while recipient != 'post1' and recipient != 'post2' and recipient != 'post3':
        recipient = input("Choisir entre post1 post2 post3:> ")

    # client = paho.Client()
    client_get_certif.connect('localhost', 5000)
    client_get_certif.publish('get_certif_client', recipient)
    client_consumer_for_client_certif(recipient)


def send_message_from_mqtt(public_key, dest):
    source = input("Tapez votre nom:> ")
    message = input("Tapez votre texte:> ")
    message_byte = message.encode('utf-8')
    # recipient = input("Tapez votre destinataire: ")

    # private_key, public_key = load_rsa_keypair()
    key = aes_gen_secret_key()

    print('************************************************************************************')
    print(public_key)
    print('************************************************************************************')

    encrypted_key = cipher_secret_key(public_key, key)

    ciphertext, key = aes_cipher(key, message_byte)

    data = {
        'recipient': dest,
        'source': source,
        'key': base64.b64encode(encrypted_key).decode('utf-8'),
        'message': base64.b64encode(ciphertext).decode('utf-8')
    }
    client_publish(data)
    print('Message sended successfully!!!')


def send_message_from_mqtt_certif(public_key, dest):
    source = input("Tapez votre nom:> ")
    while source != 'post1' and source != 'post2' and source != 'post3':
        source = input("Choisir entre post1 post2 post3:> ")
    # ***********************************************************Verify signature***************************************
    # ca_pub_key = load_and_extract_ca_pubkey(source)
    # verify_signature(ca_pub_key, signature, public_key)

    message = input("Tapez votre texte:> ")
    message_byte = message.encode('utf-8')
    # recipient = input("Tapez votre destinataire: ")
    # private_key, public_key = load_rsa_keypair()
    key = aes_gen_secret_key()
    encrypted_key = cipher_secret_key(public_key, key)
    ciphertext, key = aes_cipher(key, message_byte)
    data = {
        'recipient': dest,
        'source': source,
        'key': base64.b64encode(encrypted_key).decode('utf-8'),
        'message': base64.b64encode(ciphertext).decode('utf-8')
    }
    client_publish(data)
    print('Message sended successfully!!!')


def request_certif(csr, username):
    client = paho.Client()
    client.connect('localhost', 5000)
    data = {
        'csr': csr.decode('utf-8'),
        'username': username
    }
    payload = json.dumps(data)
    client.publish('certificat_demande', payload)
    print('Certificat_demande sended')
    client.disconnect()
    client_consumer_for_ownerCertif(username)


def on_message_client_ownerCertif(client, userdata, msg):
    print('lololoollooooooooooo')
    print(msg.topic + " " + str(msg.payload))
    print(type(msg.payload))
    # Charger le contenu du certificat depuis le message MQTT
    cert_content = msg.payload
    # Écrire le contenu du certificat dans un fichier
    with open("post1/certificat/owner_cert.pem", "wb") as f:
        f.write(cert_content)

    print("Certificat enregistré dans ca_cert.pem")


def on_client_connect_ownerCertif(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))


def client_consumer_for_ownerCertif(username):
    client = paho.Client()
    client.connect('localhost', 5000, 60)
    topic = 'return_certif' + username
    client.on_connect = on_client_connect_ownerCertif
    client.on_message = on_message_client_ownerCertif
    print(topic)

    client.subscribe(topic)
    client.disconnect()
    # client.loop_forever()
