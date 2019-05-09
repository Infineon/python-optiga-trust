from optigatrust import *

try:
	otapi = OptigaTrust()
	if otapi:
		print('Perso2Go connected.')
except:
	print('Perso2Go not connected.')
