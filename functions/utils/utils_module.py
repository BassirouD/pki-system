from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from functions.rsa.rsa_module import *
from functions.aes.my_aes_module import *
from Crypto.Cipher import PKCS1_OAEP
from client_package.rsa.rsa_module import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


def decrypt_key_decrypt_message(encrypted_key, encrypted_message, recipient):
    encrypted_key = b64decode(encrypted_key)
    encrypted_message = b64decode(encrypted_message)

    private_key, public_key = load_rsa_keypair(recipient)

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher.decrypt(encrypted_key)
    # aes_key = private_key.decrypt(encrypted_key)

    # decrypted_message = decrypt_f(encrypted_message, aes_key)

    plaintext = aes_decrypt2(key=decrypted_key, ciphertext=encrypted_message)
    return plaintext


def decrypt_key_decrypt_message2(encrypted_key, encrypted_message, recipient):
    encrypted_key = b64decode(encrypted_key)
    encrypted_message = b64decode(encrypted_message)

    private_key, public_key = load_rsa_keypair2(recipient)
    #
    # print('================>:', private_key, ' ', '=====================>', public_key)
    # print('================>:', type(private_key), ' ', '=====================>', type(public_key))

    # decrypted_key = decypt_secret_key2(private_key, encrypted_key)

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher.decrypt(encrypted_key)
    # aes_key = private_key.decrypt(encrypted_key)

    # decrypted_message = decrypt_f(encrypted_message, aes_key)

    # pas parti
    plaintext = aes_decrypt2(key=decrypted_key, ciphertext=encrypted_message)
    return plaintext


def srv_gen_certif_for_client(csr_data, username):
    csr = x509.load_pem_x509_csr(csr_data)
    # Extraire la clé publique du client
    public_key = csr.public_key()
    subject = csr.subject
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Exemple CA"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"ca@example.com"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    # charger la clé privée de la CA depuis un fichier PEM
    with open('functions/certificat/srv/certif/ca_private_key.pem', 'rb') as f:
        client_private_key_data = f.read()

    # créer un objet clé privée RSA ou ECDSA à partir de la représentation PEM
    ca_private_key = serialization.load_pem_private_key(
        client_private_key_data, password=None, backend=default_backend())

    cert = builder.sign(ca_private_key, hashes.SHA256())

    cert_byte = cert.public_bytes(serialization.Encoding.PEM)

    # charger la clé privée de la CA depuis un fichier PEM
    with open(f'functions/certificat/clients/sign_pubkeys/{username}_certif.pem', 'wb') as f:
        f.write(cert_byte)

    print('********************************')
    print('Pubkey signed successfully')
    print('********************************')

    return cert_byte
