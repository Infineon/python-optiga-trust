# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""Verify signature in software using the cryptography package

This example shows how to verify an ECDSA signature purely in software by using the Python package cryptography.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

from optigatrust import crypto, util

hash_name = "sha512"
tbs_str = b"Test String to Sign"

# Remove everything before 03.. from ASN1 public key
public_key = bytes.fromhex(
    "30819b301006072a8648ce3d020106052b810400230381860004011ce3de6154c98f065685755e1550bf4e1db5df758b897a49bf9fb59302fe08f104364adbde5bd0a2479a92aee6ee29e633832f497162dbdca8e79ed658200ab72e0073ac4e3d43dbd4921b5dbd8ee804fe555df99d22621b8e3fe736a54bfbc98c22d5f24aa3ce25e4672ffa79a3c92b5be1e67898422ebfe314d92e9df90332cec2f1"
)
# Remove everything before 02... from ASN1 signature
signature = bytes.fromhex(
    "30818702417b962d9d14ceefe4a4bcd98fa692666767a1b1d3c14bb7b7e59c85c9f1f64ea39badaadfc4815ddb76b5378252261def4b53f2e17f7def4623e9d73de16b14dc11024200f0575eb5b509baf8e7ffc6ba61f9306555a4962b72111b97d05662c8f46cfd7e9b42e1ba7a173b7185e18b04745c4537c2322887a8eec5fe934035c8a6d804965a"
)

print("Public key:")
util.print_binary(public_key)
print("Signature:")
util.print_binary(signature)

cryptography_public_key = serialization.load_der_public_key(public_key)

signature_is_valid = cryptography_public_key.verify(
    signature, tbs_str, ec.ECDSA(crypto._hash_map[hash_name][2])
)
if signature_is_valid:
    print("Signature validation successful!")
else:
    print("Signature validation failed!")
