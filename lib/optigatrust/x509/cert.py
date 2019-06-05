# ============================================================================
# The MIT License
# 
# Copyright (c) 2019 Infineon Technologies AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
# ============================================================================
import base64
import warnings
from optigatrust.util.types import *
from optigatrust.util import io


__all__ = [
	'read_existing',
	'write_new',
]


def _break_apart(f, sep, step):
	return sep.join(f[n:n + step] for n in range(0, len(f), step))


def read_existing(certid=ObjectId.IFX_CERT, to_pem=False):
	"""
	This function returns an exisiting certificate from the OPTIGA(TM) Trust device

	:param certid:
		Should be a value from the ObjectId

	:param to_pem:
		A boolean flag to indecate, whether you want return certificate PEM encoded

	:raises:
		ValueError - when any of the parameters contain an invalid value
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		A byte string with a PEM certificate or DER encoded byte string
	"""
	if not isinstance(certid, ObjectId):
		raise TypeError(
			'Certificate Slot is not correct. '
			'Supported values are in ObjectId class you used {0}'.format(certid)
		)
	if certid not in {ObjectId.IFX_CERT, ObjectId.USER_CERT_1, ObjectId.USER_CERT_2, ObjectId.USER_CERT_3}:
		warnings.warn("You are going to use an object which is outside of the standard certificate storage")

	der_cert = io.read(certid)

	print(list(der_cert))

	if len(der_cert) == 0:
		raise ValueError(
			'Certificate Slot {0} is empty'.format(certid)
		)

	# OPTIGA Trust Code to tag an X509 certificate
	if der_cert[0] == 0xC0:
		der_cert = der_cert[9:]

	if to_pem:
		pem_cert = "-----BEGIN CERTIFICATE-----\n"
		pem_cert += _break_apart(base64.b64encode(der_cert).decode(), '\n', 64)
		pem_cert += "\n-----END CERTIFICATE-----"
		return pem_cert.encode()
	else:
		return bytes(der_cert)


def _append_length(data, last=False):
	data_with_length = bytearray(3)
	left = len(data)

	data_with_length[2] = left % 0x100

	left = left >> 8
	data_with_length[1] = left % 0x100

	if last:
		data_with_length[0] = 0xC0
	else:
		left = left >> 8
		data_with_length[0] = left % 0x100

	data_with_length.extend(data)

	return data_with_length


def _strip_cert(cert):
	if cert.split('\n')[0] != "-----BEGIN CERTIFICATE-----":
		raise ValueError(
			'Incorrect Certificate '
			'Should start with "-----BEGIN CERTIFICATE-----" your starts with {0}'.format(cert.split('\n')[0])
		)
	raw_cert = cert.replace('-----BEGIN CERTIFICATE-----', '')
	raw_cert = raw_cert.replace('-----END CERTIFICATE-----', '')
	raw_cert = raw_cert.replace("\n", "")
	der_cert = base64.b64decode(raw_cert)

	return der_cert


def write_new(cert, certid=ObjectId.USER_CERT_1):
	"""
	This function writes a new certificate into the OPTIGA(TM) Trust device

	:param cert:
		Should be a a string with a PEM file with newlines separated or a bytes insatnce with DER encoded cert

	:param certid:
		Should be a value from the ObjectId

	:raises:
		ValueError - when any of the parameters contain an invalid value
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		None
	"""
	if not isinstance(certid, ObjectId):
		raise TypeError(
			'Certificate Slot is not correct. '
			'Supported values are in ObjectId class you used {0}'.format(certid)
		)

	if certid not in {ObjectId.IFX_CERT, ObjectId.USER_CERT_1, ObjectId.USER_CERT_2, ObjectId.USER_CERT_3}:
		warnings.warn("You are going to use an object which is outside of the standard certificate storage")

	if not isinstance(cert, str) and not isinstance(cert, bytes) and not isinstance(cert, bytearray):
		raise TypeError(
			'Bad certificate type should be either bytes, bytes string, or string'
		)

	# Looks like a DER encoded files has been provided
	if isinstance(cert, bytes) or isinstance(cert, bytearray):
		try:
			cert = cert.decode("utf-8")
			cert = _strip_cert(cert)
		except UnicodeError:
			pass
	elif isinstance(cert, str):
		cert = _strip_cert(cert)
	else:
		raise TypeError(
			'Bad certificate type should be either bytes, bytes string, or string'
		)

	der_cert = cert

	if der_cert[0] != 0x30:
		raise ValueError(
			'Incorrect Certificate '
			'Should start with 0x30 your starts with {0}'.format(der_cert[0])
		)

	# Append tags
	# [len_byte_2, len_byte_1, len_byte_0] including the certificate and two lengths
	#   [len_byte_2, len_byte_1, len_byte_0] including the certificate and the length
	#       [len_byte_2, len_byte_1, len_byte_0]
	#           [der_encoded_certificate]
	# Write the result into the given Object ID
	l1_der_cert = _append_length(der_cert)
	l2_der_cert = _append_length(l1_der_cert)
	l3_der_cert = _append_length(l2_der_cert, last=True)

	# print("Certificate without encoding #1 {0}".format(list(der_cert)))
	# print("Certificate without encoding #2 {0}".format(list(l1_der_cert)))
	# print("Certificate without encoding #3 {0}".format(list(l2_der_cert)))
	# print("Certificate without encoding #4 {0}".format(list(l3_der_cert)))

	io.write(l3_der_cert, certid)
