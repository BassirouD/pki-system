from client_package.mqtt.mqtt_module import *

if __name__ == '__main__':
    # gen_rsa_key('post3')
    # client_consumer('post2')
    has_certif = os.path.exists(f'post2/rsa/public_key.pem')
    if has_certif:
        print('Already has certif')
    else:
        gen_key_client('post2')
    client_consumer2('post2')
    # client_get_certif_client_from_srv()

    # client_shared_pubkey('post2')
    # gen_rsa_key('post2')

# https://youtube.com/shorts/Wld7BXJfV9Q?feature=share