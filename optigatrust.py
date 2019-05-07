from ctypes import *
import os

class OptigaTrust:
	def __init__(self, api=None):
		"""
		load OptigaTrust into Python
		raise an exception library can't be loaded
		"""
		self.api = api
		if api is None:
			curr_path = os.path.abspath(os.path.dirname(__file__) + "/liboptigatrust/library/")
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
    
