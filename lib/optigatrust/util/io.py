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

from optigatrust.util import chip
from optigatrust.util.types import *


def read(object_id, offset=0):
	"""
	This function helps to read the data stored on the chip

	:param object_id:
		An ID of the Object. Should be ObjectId

	:param offset:
		An optional parameter defining whether you want to read the data with offset

	:raises
		ValueError - when any of the parameters contain an invalid value
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		bytearray with the data
	"""
	api = chip.init()

	if offset > 1700:
		raise ValueError("offset should be less than the limit of 1700 bytes")

	if not isinstance(object_id, ObjectId):
		raise TypeError("You need to provide an ObjectId you provided {0}".format(object_id))

	api.optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
	api.optiga_util_read_data.restype = c_int

	d = (c_ubyte * 1700)()
	c_dlen = c_ushort(1700)

	ret = api.optiga_util_read_data(c_ushort(object_id.value), offset, d, byref(c_dlen))

	if ret == 0 and not all(_d == 0 for _d in list(bytes(d))):
		data = (c_ubyte * c_dlen.value)()
		memmove(data, d, c_dlen.value)
		_bytes = bytearray(data)
	else:
		_bytes = bytearray(0)

	return _bytes


def write(data, object_id, offset=0):
	"""
	This function helps to write the data stored on the chip

	:param data:
		Data to write, should be either bytes of bytearray

	:param object_id:
		An ID of the Object. Should be ObjectId

	:param offset:
		An optional parameter defining whether you want to read the data with offset

	:raises
		ValueError - when any of the parameters contain an invalid value
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
	"""
	api = chip.init()

	if not isinstance(data, bytes) and not isinstance(data, bytearray):
		raise TypeError("data should be bytes type")

	if not isinstance(object_id, ObjectId):
		raise TypeError(
			'keyid should be KeyId type,'
			'you gave {0}'.format(type(object_id))
		)

	if len(data) > 1700:
		raise ValueError("length of data exceeds the limit of 1700")

	if offset > 1700:
		raise ValueError("offset should be less than the limit of 1700 bytes")

	api.optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
	api.optiga_util_write_data.restype = c_int

	_data = (c_ubyte * len(data))(*data)

	ret = api.optiga_util_write_data(c_ushort(object_id.value), 0x40, offset, _data, len(data))

	if ret != 0:
		raise ValueError(
			'Some problems during communication. You have possible selected one of locked objects'
		)
