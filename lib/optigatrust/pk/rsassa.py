# ============================================================================
# The MIT License
#
# Copyright (c) 2018 Infineon Technologies AG
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

import hashlib
import warnings
from ctypes import *

from optigatrust.pk import RsaKey, RsassaSignature
from optigatrust.util import chip


def sign(rsakey, data, hash_algorithm='sha256'):
	"""
	This function signs given data based on the provided RsaKey object

	:param rsakey:
		a valid RsaKey object. Use rsa.generate_keypair() for this

	:param data:
		Data to sign

	:param hash_algorithm:
		Hash algorithm which should be used to sign data. SHA256 by default

	:raises:
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		RsassaSignature object or None
	"""
	api = chip.init()

	if not chip.is_trustm():
		raise TypeError('You are trying to use Trust M API with the Trust X hardware')

	if not isinstance(data, bytes) and not isinstance(data, bytearray):
		if isinstance(data, str):
			_d = bytes(data.encode())
			warnings.warn("data will be converted to bytes type before signing")
		else:
			raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
	else:
		_d = data

	if not isinstance(rsakey, RsaKey):
		raise TypeError('Key ID should be selected of class KeyId')

	api.optiga_crypt_rsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
	api.optiga_crypt_rsa_sign.restype = c_int

	if hash_algorithm == 'sha256':
		digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
		s = (c_ubyte * 320)()
		# Signature schemes RSA SSA PKCS1-v1.5 with SHA256 digest
		sign_scheme = 0x01
	elif hash_algorithm == 'sha384':
		digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
		s = (c_ubyte * 320)()
		# Signature schemes RSA SSA PKCS1-v1.5 with SHA384 digest
		sign_scheme = 0x02
	else:
		raise ValueError('This key isze is not supported, you typed {0} supported are [\'sha256\', \'sha384\']'
						.format(hash_algorithm))
	c_slen = c_uint(len(s))

	ret = api.exp_optiga_crypt_rsa_sign(sign_scheme, digest, len(digest), rsakey.keyid.value, s, byref(c_slen), 0)

	if ret == 0:
		signature = (c_ubyte * c_slen.value)()
		memmove(addressof(signature), s, c_slen.value)
		print(bytes(signature))
		return RsassaSignature(hash_algorithm, rsakey.keyid, bytes(signature))
	else:
		warnings.warn("Failed to sign a data, return a NoneType")
		return None
