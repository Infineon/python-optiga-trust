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
import inspect
import re
import textwrap

from optigatrust.util.types import *


__all__ = [
	'Key',
	'EccKey',
	'RsaKey',
	'Signature',
	'EcdsaSignature',
	'RsassaSignature',
	'ecc',
	'rsa',
	'ecdsa',
	'rsassa'
]


class Key:
	def __init__(self, pkey, keyid, algorithm):
		if not isinstance(pkey, bytes):
			raise TypeError(_pretty_message(''' pkey must be an instance of bytes, not %s ''', _type_name(pkey)))
		self._pkey = pkey

		if not isinstance(keyid, KeyId):
			raise TypeError(
				_pretty_message(''' pkey must be an instance of optigatrust.util.KeyId, not %s ''', _type_name(pkey)))
		self._keyid = keyid

		allowed_algorithms = set({'ec', 'rsa'})
		if algorithm in allowed_algorithms:
			self._algorithm = algorithm
		else:
			raise ValueError(_pretty_message(
				''' algorithm must be within allowed values {0}, not {1} '''.format(allowed_algorithms, algorithm)))

	@property
	def pkey(self):
		return self._pkey

	@property
	def keyid(self):
		return self._keyid

	@property
	def algorithm(self):
		return self._algorithm


class EccKey(Key):
	def __init__(self, pkey, keyid, curve):
		super().__init__(pkey, keyid, 'ec')

		allowed_curves = set({'secp256r1', 'secp384r1'})
		if curve not in allowed_curves:
			raise ValueError("Supported curves {0} you provided {1}".format(allowed_curves, curve))
		self._curve = curve

	@property
	def curve(self):
		return self._curve


class RsaKey(Key):
	def __init__(self, pkey, keyid, key_size):
		super().__init__(pkey, keyid, 'rsa')

		allowed_key_sizes = set({1024, 2048})
		if key_size not in allowed_key_sizes:
			raise ValueError("Supported key sizes {0} you provided {1}".format(allowed_key_sizes, key_size))
		self._key_size = key_size

	@property
	def key_size(self):
		return self._key_size


class Signature:
	def __init__(self, hash_alg, keyid, signature, algorithm):
		allowed_hash = set({'sha256', 'sha384'})
		if hash_alg not in allowed_hash:
			raise ValueError("not supported hash algorithm, supported {0}, you used {1}".format(allowed_hash, hash_alg))
		self._hash_alg = hash_alg

		if not isinstance(keyid, KeyId):
			raise TypeError("keyid must be instance of KeyId")
		self._keyid = keyid

		if not isinstance(signature, bytes):
			raise ValueError("signature should be instance of bytes")

		self._signature = signature

		allowed_algorithms = set({'sha256_ecdsa', 'sha384_ecdsa',
								'sha256_rsa', 'sha384_rsa'})
		if algorithm in allowed_algorithms:
			self._algorithm = algorithm
		else:
			raise ValueError(_pretty_message(
				''' algorithm must be within allowed values {0}, not {1} '''.format(allowed_algorithms, algorithm)))

	@property
	def hash_alg(self):
		return self._hash_alg

	@property
	def keyid(self):
		return self._keyid

	@property
	def signature(self):
		return self._signature

	@property
	def algorithm(self):
		return self._algorithm


class EcdsaSignature(Signature):
	def __init__(self, hash_alg, keyid, signature):
		signature_algorithm_id = '%s_%s' % (hash_alg, 'ecdsa')
		super().__init__(hash_alg, keyid, signature, signature_algorithm_id)


class RsassaSignature(Signature):
	def __init__(self, hash_alg, keyid, signature):
		signature_algorithm_id = '%s_%s' % (hash_alg, 'rsa')
		super().__init__(hash_alg, keyid, signature, signature_algorithm_id)


def _pretty_message(string, *params):
	"""
	Takes a multi-line string and does the following:
	 - dedents
	 - converts newlines with text before and after into a single line
	 - strips leading and trailing whitespace
	:param string:
		The string to format
	:param *params:
		Params to interpolate into the string
	:return:
		The formatted string
	"""

	output = textwrap.dedent(string)

	# Unwrap lines, taking into account bulleted lists, ordered lists and
	# underlines consisting of = signs
	if output.find('\n') != -1:
		output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

	if params:
		output = output % params

	output = output.strip()

	return output


def _type_name(value):
	"""
	:param value:
		A value to get the object name of
	:return:
		A unicode string of the object name
	"""

	if inspect.isclass(value):
		cls = value
	else:
		cls = value.__class__
	if cls.__module__ in set(['builtins', '__builtin__']):
		return cls.__name__
	return '%s.%s' % (cls.__module__, cls.__name__)

