# SPDX-FileCopyrightText: 2025 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""ECDSA Signature Creation and Verification with OID 0xE0E0

This example shows how to create an ECDSA signature using the Infineon pre-provisioned key pair (OID 0xE0F0) and how to
verify the respective signature with the Infineon pre-provisioned certificate (OID 0xE0E0).

NOTE: The pre-provisioned certificate with OID 0xE0E0 is stored with TLS identity (tag 0xC0 when reading out the full
certificate with `cert_object.read()`. Thus, it cannot directly be used to validate a signature. However, when copying
the DER data of the certificate to a different OID (e.g. 0xE0E3), it can be used for validation.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from optigatrust import objects, crypto, util

hash_name = "sha256"
data = b"Test String to sign"


key_oid = 0xE0F0
cert_oid = 0xE0E0
cert_validate_oid = 0xE0E3

# Create signature via OPTIGA™ Trust M
ecc_key = objects.ECCKey(key_oid)
signature = crypto.ecdsa_sign_with_hash(ecc_key, data, hash_name).signature

print("Signature:\n{0}".format(util.binary_to_hex(signature)))

# Read DER data of Infineon pre-provisioned certificate from OPTIGA™ Trust M
# See: 0xC0 tag for the TLS identity
cert_object = objects.X509(cert_oid)
print("Certificate (0x{0:02x}):\n{1}".format(cert_oid, util.binary_to_hex(cert_object.read())))

# Create a certificate object for validation (with removed tag for TLS identity)
cert_validate_object = objects.X509(cert_validate_oid)
cert_validate_object.der = cert_object.der
cert_validate_object.write(cert_validate_object.der)
print(
    "Certificate (0x{0:02x}):\n{1}".format(
        cert_validate_oid, util.binary_to_hex(cert_validate_object.read())
    )
)

# Verify signature via OPTIGA™ Trust M using OID of certificate
signature_is_valid = crypto.ecdsa_verify_data_oid(signature, data, hash_name, cert_validate_oid)
if signature_is_valid:
    print("Signature validation successful!")
else:
    print("Signature validation failed!")
