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
from ctypes import *
import warnings

from optigatrust.pk import RsaKey
from optigatrust.util import chip
from optigatrust.util.types import KeyId, KeyUsage


def generate_keypair(key_size='1024', keyid=KeyId.RSA_KEY_E0FC):
	"""
	This function generates an RSA keypair, the private part is stored on the chip based on the provided slot

	:param key_size:
		Size of the key, can be 1024 or 2048

	:param keyid:
		A Private Key Slot object ID. The value should be within the KeyId Enumeration

	:raises:
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		RsaKey object or None
	"""
	_bytes = None
	api = chip.init()

	if not chip.is_trustm():
		raise TypeError('You are trying to use Trust M API with the Trust X hardware')

	allowed_key_sizes = {'1024', '2048'}
	if key_size not in allowed_key_sizes:
		raise ValueError('This key size is not supported, you typed {0} (type {1}) supported are [1024, 2048]'.
						format(key_size, type(key_size)))

	if keyid not in KeyId:
		raise TypeError('Key ID should be selected of class KeyId')

	api.exp_optiga_crypt_rsa_generate_keypair.argtypes = c_int, c_ubyte, c_bool, c_void_p, POINTER(c_ubyte), POINTER(c_ushort)
	api.exp_optiga_crypt_rsa_generate_keypair.restype = c_int

	if key_size is '1024':
		c_keytype = 0x41
		rsa_header = b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00'
	else:
		c_keytype = 0x42
		rsa_header = b'\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
	c_keyusage = c_ubyte(KeyUsage.KEY_AGREEMENT.value | KeyUsage.AUTHENTICATION.value | KeyUsage.ENCRYPTION.value)
	c_keyid = c_ushort(keyid.value)
	p = (c_ubyte * 320)()
	c_plen = c_ushort(len(p))

	ret = api.exp_optiga_crypt_ecc_generate_keypair(c_keytype, c_keyusage, 0,  byref(c_keyid), p, byref(c_plen))

	pubkey = (c_ubyte * c_plen.value)()
	memmove(pubkey, p, c_plen.value)

	if ret == 0:
		return RsaKey(pkey=rsa_header + bytes(pubkey), keyid=keyid, key_size=int(key_size))
	else:
		raise ValueError('Failed to generate an RSA keypair, return a NoneType')

