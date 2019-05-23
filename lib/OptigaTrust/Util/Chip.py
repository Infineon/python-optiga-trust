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
import os
import platform
import sys
from OptigaTrust.Util.Defines import *

optiga_initialised = False
optiga_lib_handler = None

def _get_arch_os():
	platforms = {
		'linux' : 'Linux',
		'linux1': 'Linux',
		'linux2': 'Linux',
		'darwin': 'OSX',
		'cygwin': 'Windows',
		'msys'  : 'Windows',
		'win32' : 'Windows',
	}

	if sys.platform not in platforms:
		return sys.platform
	
	return platform.architecture()[0], platforms[sys.platform]

def _get_lib_postfix():
	targets = {
		'Linux'  : {
			'32bit' : 'x86',
			'64bit' : 'x86_64'
		},
		'Windows': {
			'32bit' : 'ms32',
			'64bit' : 'ms64',
		}
	}
	arch_os = _get_arch_os()
	
	if arch_os[1] not in targets:
		raise Exception('Platform not supported')

	return targets[arch_os[1]][arch_os[0]]

def init():
	"""
	load OptigaTrust into Python
	raise an exception library can't be loaded
	Initialise only one, afterwards return the library handler
	"""
	global optiga_initialised
	global optiga_lib_handler
	
	if not optiga_initialised and optiga_lib_handler is None :
		lib_postfix = _get_lib_postfix()

		curr_path = os.path.abspath(os.path.dirname(__file__) + "/../../../src/library/" + lib_postfix)

		print(curr_path)

		os.chdir(curr_path)
		if os.path.exists(os.path.join(curr_path, "liboptigatrust.so")):
			api = cdll.LoadLibrary(os.path.join(curr_path, "liboptigatrust.so"))
		elif os.path.exists(os.path.join(curr_path, "OptigaTrust.dll")):
			api = cdll.LoadLibrary(os.path.join(curr_path, "OptigaTrust.dll"))
		else:
			api = None
			raise Exception('Unable to find library in {}'.format(curr_path))
		api.optiga_init.restype = c_int
		ret = api.optiga_init()
		if ret != 0:
			raise Exception('Failed to initialise the chip. Exit.')
		
		optiga_initialised = True
		optiga_lib_handler = api

	return optiga_lib_handler
	
def deinit():
	global optiga_initialised
	global optiga_lib_handler

	optiga_initialised = False
	optiga_lib_handler = None
	
def fwversion():
	pass
	
def uid():
	return UID()