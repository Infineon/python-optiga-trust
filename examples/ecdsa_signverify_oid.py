# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""ECDSA Signature Creation and Verification with OID

This example shows how to create an ECDSA signature using the OID of a private key stored in the OPTIGA™ Trust M device.
Furthermore, it shows how to verify the ECDSA signature using the OID of a certificate stored in the OPTIGA™ Trust M
device.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from optigatrust import objects, crypto, util

from cryptography.hazmat.primitives import serialization

hashname = "sha256"
data = b"Test String to sign"


key_oid = 0xE0F3
cert_oid = 0xE0E3

# Create a key pair in OPTIGA™ Trust M for signature creation
ecc_key = objects.ECCKey(key_oid)
trust_public_key, _ = crypto.generate_pair(ecc_key, curve="secp256r1", export=False)
print(
    "OPTIGA™ Trust M - Slot 0x{0:02x} - Public key:\n{1}".format(
        key_oid, util.binary_to_hex(trust_public_key)
    )
)

# Create signature via OPTIGA™ Trust M
signature = crypto.ecdsa_sign_with_hash(ecc_key, data, hashname).signature

print("Signature:\n{0}".format(util.binary_to_hex(signature)))

cert = util.generate_ephemeral_certificate(trust_public_key)
cert_der = cert.public_bytes(serialization.Encoding.DER)

print("Certificate:\n{0}".format(util.binary_to_hex(cert_der)))

# Write certificate to OPTIGA™ Trust M
cert_object_new = objects.X509(cert_oid)
cert_object_new.der = cert_der
cert_object_new.write(cert_object_new.der)

# Verify signature via OPTIGA™ Trust M using public key from host
signature_is_valid = crypto.ecdsa_verify_data_oid(signature, data, hashname, cert_oid)
if signature_is_valid:
    print("Signature validation successful!")
else:
    print("Signature validation failed!")
