from client_package.rsa.rsa_module import *
from client_package.mqtt.mqtt_module import *

if __name__ == '__main__':
    # gen_rsa_key('post3')
    # client_consumer()
    # client_shared_pubkey('post2')
    # gen_rsa_key('post2')
    # client_shared_pubkey('post3')
    # client_consumer('post3')

    # ******************************************
    has_certif = os.path.exists(f'post3/rsa/public_key.pem')
    if has_certif:
        print('Already has certif')
    else:
        gen_key_client('post3')
    client_consumer2('post3')
    # client_get_certif_client_from_srv()
    # ******************************************


    # client_get_ca_certif('post3')
