from functions.mqtt.mqtt_module import *
from functions.certificat.srv.certif_server_module import *


def gen_cert():
    isExist = os.path.exists('functions/certificat/srv/certif/key.pem')
    if isExist:
        print('Certification already exist!!')
        return True
    else:
        gen_certification()
        return False


if __name__ == '__main__':
    gen_cert()
    star_loop_mqtt_server('localhost')
