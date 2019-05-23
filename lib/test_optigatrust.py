from OptigaTrust.Random import *
from OptigaTrust.PublicKey import ECC

print("Random size 8 bytes: {0}\n".format(list(get_random_bytes(8))))
print("Random size 16 bytes: {0}\n".format(list(get_random_bytes(16))))
print("Random size 255 bytes: {0}\n".format(list(get_random_bytes(255))))
print("Generate NIST-P256 Keypair: {0}\n".format(list(ECC.generate())))
print("Generate NIST-P384 Keypair: {0}\n".format(list(ECC.generate(curve="nistp384"))))
