Object and Metadata Management
==============================

Objects
^^^^^^^

Reading a certificate object
----------------------------

::

	from optigatrust.cert import *
	
	cert_object = Certificate(0xe0e0)
	print(cert_object)
	
Reading a key object
--------------------

::

	from optigatrust.asymmetric import *
	import json
	
	key_object = EccKey(0xe0f0)
	print(json.dumps(key_object.meta, indent=4))

Metadata
^^^^^^^^

Printing All metadata in human readbale form
--------------------------------------------

::

	from optigatrust.cert import *
	import json
	
	cert_object = Certificate(0xe0e0)
	print(json.dumps(cert_object.meta, indent=4))
	
	
Updating Metadata of the Certificate Object
--------------------------------------------

::

	from optigatrust.cert import *
	
	cert_object = Certificate(0xe0e0)

	# Print out certificate sucessfully
	print(cert_object)
	
	# Store old metadata from the chip
	old_meta = cert_object.meta['read']
	
	# Prepare new metadata to write on the chip
	new_meta = {'read': 'never'}
	
	# Update metadata on the chip
	cert_object.meta = new_meta
	
	# Try to read-out the content one more time. Result: Value Error
	print(cert_object)
	
	# Revert the metadata
	cert_object.meta = old_meta
	
	# See that printing is again possible
	print(cert_object)
	
Sample output ::
	
	C:\Users\User\git\python-optiga-trust>python
	Python 3.8.1 (tags/v3.8.1:1b293b6, Dec 18 2019, 22:39:24) [MSC v.1916 32 bit (Intel)] on win32
	Type "help", "copyright", "credits" or "license" for more information.
	>>> from optigatrust.cert import *
	>>> cert_object = Certificate(0xe0e0)
	Loaded: liboptigatrust-libusb-win-i686.dll
	================== OPTIGA Trust Chip Info ==================
	Firmware Identifier           [dwFirmwareIdentifier]:0x80101071
	Build Number                  [rgbESWBuild]:0x809
	Current Limitation            [OID: 0xE0C4]:0xf
	Sleep Activation Delay        [OID: 0xE0C3]:0x14
	Global Lifecycle State        [OID: 0xE0C0]:operational
	Security Status               [OID: 0xE0C1]:0x0
	Security Event Counter        [OID: 0xE0C5]:0x0
	============================================================
	>>> print(cert_object)
	================== Certificate Object [0xe0e0] ==================
	Lifecycle State               :creation
	Size                          :485
	Access Condition: Read        :always
	Access Conditions: Change     :never
	PEM                           :
	b'-----BEGIN CERTIFICATE-----
	MIIB2DCCAX6gAwIBAgIEa9mwITAKBggqhkjOPQQDAjByMQswCQYDVQQGEwJERTEh
	MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRMwEQYDVQQLDApPUFRJ
	R0EoVE0pMSswKQYDVQQDDCJJbmZpbmVvbiBPUFRJR0EoVE0pIFRydXN0IE0gQ0Eg
	MTAxMB4XDTE5MDYxODA2MjgyM1oXDTM5MDYxODA2MjgyM1owHDEaMBgGA1UEAwwR
	SW5maW5lb24gSW9UIE5vZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxjN/R
	RdonS92dwYnvIIZnD0HrIhYg9lcZsSv3urXRnjL/xVEs/ijCzWKCQruY2CsTv2jg
	iemizjIl4jURWfa9o1gwVjAOBgNVHQ8BAf8EBAMCAIAwDAYDVR0TAQH/BAIwADAV
	BgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFDwwjFzViuijXTKA5FSD
	sv/Nhk0jMAoGCCqGSM49BAMCA0gAMEUCIDdnY4NzhosPawMGoY138J6uHzsLU6nZ
	euBnZOnwnlwzAiEAkXneR8Gzkrk1S6f9zva8J6fe8LYejW15eXOwDyt7Nss=
	-----END CERTIFICATE-----'
	Issuer: Common Name           :Infineon OPTIGA(TM) Trust M CA 101
	Subject: Common Name          :Infineon IoT Node
	Public Key                    :04f18cdfd145da274bdd9dc189ef2086670f41eb221620f65719b12bf7bab5d19e32ffc5512cfe28c2cd628242bb98d82b13bf68e089e9a2ce3225e2351159f6bd
	Signature                     :304502203767638373868b0f6b0306a18d77f09eae1f3b0b53a9d97ae06764e9f09e5c330221009179de47c1b392b9354ba7fdcef6bc27a7def0b61e8d6d797973b00f2b7b36cb
	============================================================
	>>> old_meta = cert_object.meta['read']
	>>> new_meta = {'read': 'never'}
	>>> cert_object.meta = new_meta
	>>> print(cert_object)
	Error: 0x8007
	Traceback (most recent call last):
	  File "<stdin>", line 1, in <module>
	  File "C:\Users\Yushev\git\python-optiga-trust\optigatrust\cert.py", line 613, in __str__
		pem = '{0:<30}:\n{1}\n'.format("PEM", str(self.pem).replace('\\n', '\n').replace('\\t', '\t'))
	  File "C:\Users\Yushev\git\python-optiga-trust\optigatrust\cert.py", line 642, in pem
		pem_cert += _break_apart(base64.b64encode(self.der).decode(), '\n', 64)
	  File "C:\Users\Yushev\git\python-optiga-trust\optigatrust\cert.py", line 632, in der
		self._der = self._read()
	  File "C:\Users\Yushev\git\python-optiga-trust\optigatrust\cert.py", line 768, in _read
		raise ValueError(
	ValueError: Certificate Slot 57568 is empty
	>>> cert_object.meta = old_meta
	>>> print(cert_object)
	================== Certificate Object [0xe0e0] ==================
	Lifecycle State               :creation
	Size                          :485
	Access Condition: Read        :always
	Access Conditions: Change     :never
	PEM                           :
	b'-----BEGIN CERTIFICATE-----
	MIIB2DCCAX6gAwIBAgIEa9mwITAKBggqhkjOPQQDAjByMQswCQYDVQQGEwJERTEh
	MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRMwEQYDVQQLDApPUFRJ
	R0EoVE0pMSswKQYDVQQDDCJJbmZpbmVvbiBPUFRJR0EoVE0pIFRydXN0IE0gQ0Eg
	MTAxMB4XDTE5MDYxODA2MjgyM1oXDTM5MDYxODA2MjgyM1owHDEaMBgGA1UEAwwR
	SW5maW5lb24gSW9UIE5vZGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxjN/R
	RdonS92dwYnvIIZnD0HrIhYg9lcZsSv3urXRnjL/xVEs/ijCzWKCQruY2CsTv2jg
	iemizjIl4jURWfa9o1gwVjAOBgNVHQ8BAf8EBAMCAIAwDAYDVR0TAQH/BAIwADAV
	BgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFDwwjFzViuijXTKA5FSD
	sv/Nhk0jMAoGCCqGSM49BAMCA0gAMEUCIDdnY4NzhosPawMGoY138J6uHzsLU6nZ
	euBnZOnwnlwzAiEAkXneR8Gzkrk1S6f9zva8J6fe8LYejW15eXOwDyt7Nss=
	-----END CERTIFICATE-----'
	Issuer: Common Name           :Infineon OPTIGA(TM) Trust M CA 101
	Subject: Common Name          :Infineon IoT Node
	Public Key                    :04f18cdfd145da274bdd9dc189ef2086670f41eb221620f65719b12bf7bab5d19e32ffc5512cfe28c2cd628242bb98d82b13bf68e089e9a2ce3225e2351159f6bd
	Signature                     :304502203767638373868b0f6b0306a18d77f09eae1f3b0b53a9d97ae06764e9f09e5c330221009179de47c1b392b9354ba7fdcef6bc27a7def0b61e8d6d797973b00f2b7b36cb
	============================================================