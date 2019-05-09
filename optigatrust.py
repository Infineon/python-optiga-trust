from ctypes import *
import os
import platform
import sys

def get_arch_os():
	platforms = {
		'linux' : 'Linux',
		'linux1': 'Linux',
		'linux2': 'Linux',
		'darwin': 'OSX',
		'cygwin': 'Windows',
		'win32' : 'Windows',
	}

	if sys.platform not in platforms:
		return sys.platform
	
	return (platform.architecture()[0], platforms[sys.platform])

def get_lib_postfix():
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
	arch_os = get_arch_os()

	if arch_os[1] not in targets:
		raise Exception('Platform not supported')

	return targets[arch_os[1]][arch_os[0]]

class OptigaTrust:
	def __init__(self, api=None):
		"""
		load OptigaTrust into Python
		raise an exception library can't be loaded
		"""
		self.api = api
		if api is None:
			lib_postfix = get_lib_postfix()

			curr_path = os.path.abspath(os.path.dirname(__file__) + "/liboptigatrust/library/" + lib_postfix)
			os.chdir(curr_path)
			if os.path.exists(os.path.join(curr_path, "liboptigatrust.so")):
				self.api = cdll.LoadLibrary(os.path.join(curr_path, "liboptigatrust.so"))
			elif os.path.exists(os.path.join(curr_path, "OptigaTrust.dll")):
				self.api = cdll.LoadLibrary(os.path.join(curr_path, "OptigaTrust.dll"))
			else:
				self.api = None
				raise Exception('Unable to find library in {}'.format(curr_path))
		self.api.optiga_init.restype = c_int
		ret = self.api.optiga_init()
		if ret != 0:
			raise Exception('Failed to initialise the chip. Exit.')
    
