import pytest
import os
from optigatrust.util.io import *
import logging

LOGGER = logging.getLogger(__name__)
pytest.test_dir = os.path.dirname(__file__)

def test_read_metadata():
	LOGGER.info('Read Metadata')
	c = read_meta(ObjectId.USER_CERT_1)
	assert isinstance(c, bytearray)

def test_write_metadata():
	#read current metadata
	LOGGER.info('Write Metadata1')
	ret = 1
	c = read_meta(ObjectId.USER_CERT_1)
	LOGGER.info(c)
	for i in range (len(c)):
		if((c[i])==(0xD0)):
			temp = c[i+2]

	#change the metadata	
	if(temp == 0xFF):
		testWrite = 0x00
	else:
		testWrite = 0xFF
	data = [0x20,0x03,0xD0,0x01, testWrite]
	write_meta(bytes(data),ObjectId.USER_CERT_1)

	#read metadata again, check if the change happened
	c = read_meta(ObjectId.USER_CERT_1)
	LOGGER.info(c)
	for i in range (len(c)):
		if((c[i])==(0xD0)):
			if(c[i+2]==testWrite):
				ret = 0
				break
			else:
				ret = 1
	
	#set the metadata in its starting state
	data2 = [0x20,0x03,0xD0,0x01, temp]
	write_meta(bytes(data2),ObjectId.USER_CERT_1)
	
	if(ret == 1):
		assert False
