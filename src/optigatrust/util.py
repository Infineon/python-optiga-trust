#!/usr/bin/env python

# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import logging
import textwrap
import datetime

DEFAULT_LOG_LEVEL = logging.WARN


class MultiLineFormatter(logging.Formatter):
    def format(self, record):
        message = str(record.msg)
        record.msg = ""
        header = super().format(record)
        msg = textwrap.indent(message, " " * len(header)).lstrip()
        record.msg = message
        return header + msg


class Logger(logging.Logger):
    def __init__(self, name, level=None):
        if level is None:
            level = DEFAULT_LOG_LEVEL
        super().__init__(name, level)
        self.extra_info = None

        formatter = MultiLineFormatter(
            fmt="%(levelname)-8s %(name)-20s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(formatter)
        self.addHandler(log_handler)


def print_binary(binary_data):
    print(binary_to_hex(binary_data))


def binary_to_hex(binary_data):
    if not isinstance(binary_data, bytes):
        binary_data = bytes(binary_data)

    output = ""
    for i in range(len(binary_data)):
        if i > 0:
            if i % 16 == 0:
                output += "\n"
            else:
                output += " "
        output += binary_data[i : i + 1].hex()

    return output


def generate_ephemeral_certificate(public_key):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    # Create key pair for self-signed certificate
    ca_private_key = ec.generate_private_key(ec.SECP256R1())

    # Create a certificate for the OPTIGA Trust key
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bavaria"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Munich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Infineon Technologies AG"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OPTIGA Trust Test CA"),
        ]
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(serialization.load_der_public_key(public_key))
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
