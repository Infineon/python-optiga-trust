Object and Metadata Management
==============================

Objects
^^^^^^^

An object within this library is a generic class, which represents basic functionality and features valid for all
OIDs (Object IDs) located on one chip.
Here are basic features what you can do with a generic Object instance (if access condition allows):
 - Read/write data from/to the object
 - Read/write metadata from/to the object
::

    from optigatrust import core

    # Create an instance of object.
    object = Object(0xf1d0)

    # Read data


A Certificate object
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

Options
-------
Users can work with metadata directly in human-readable form.
Metadata should be contructed in the following manner::

	{'<metadata_tag>': '<metadata_value>'}
	
Where metadata can take the following values:

Metadata Tags
+++++++++++++

All metadata can be changed (except for OPTIGA Trust M V3) only if the lifecycle state of the object is either 'creation' or 'initialisation'

.. list-table:: Metadata Tags Table
   :widths: 10 30 70
   :header-rows: 1

   * - Tag
     - Expected values
     - Meaning
   * - 'execute'
     - Values are defined in the Access Conditions Table below
     - Define Execute Access Condition for the object. In other words under which conditions the chip can make use of the object **internally**; e.g. signature generation using object 0xe0f1.
   * - 'change'
     - Values are defined in the Access Conditions Table below
     - Define Change Access Condition for the object. Define when it's possible to update/overwrite the object.
   * - 'read'
     - Values are defined in the Access Conditions Table below
     - Define Read Access Condition for the object. Define when it's possible to read the object.
   * - 'lcso'
     - ['creation', 'initialisation', 'operational', 'termination']
     - Define lifecycle state of the object. Attention, in most of cases this action is one-way
   * - 'max_size'
     - integer
     - Automatically calculated by the chip, can't be defined by a user
   * - 'used_size'
     - integer
     - Automatically calculated by the chip, can't be defined by a user
   * - 'algorithm'
     - Automatically set by the chip, can't be defined by a user
     - This tag is applicable only for Key Objects. The chip selects automatically the value for this tag based on the keypair generation parameters.
   * - 'key_usage'
     - [ 'authentication', 'encryption', 'sign', 'key_agreement']
     - This tag is applicable only for Key Objects. It can be defined in a list to reflect multiple options; e.g. {'key_usage': [[ 'authentication', 'sign', 'key_agreement']]}
   * - 'type'
     - Refer to the types Table below
     - Type of the object. Some functions; e.g. hmac, do work only if a specific type is defined
   * - 'reset_type'
     -
     - It defines what happens with the object data in case of updating the metadata

Access Conditions
+++++++++++++++++

The '<metadata_value>' should be defined either as a list of values; e.g.

 - a constructed value
    - {'read': ['lcso', '<', 'operational']}
    - Read is allowed only if the lifecycle state of the object is less than operational
 - a more complex constructed value
    - {'read': ['lcso', '<', 'operational', '&&', 'conf', 'e1', '40']}
    - Read is allowed only if the lifecycle state of the object is less than operation and under shielded connection (using e140 OID as a binding secret)


.. list-table:: Access Conditions Table (SRM M V3 - Table 69)
   :widths: 10 90
   :header-rows: 1

   * - Tag
     - Meaning
   * - 'always'
     - an action (for instance 'read') is always allowed
   * - 'never'
     - an action (for instance 'read') is forbidden
   * - 'lcsg'
     - Global Lifecycle State (Object ID 0xe0c0) this tag is used as a first argument for a complex expressions; e.g. ['lcsg', '<', 'operational']
   * - 'lcsa'
     -  Application Lifecycle State (Object ID 0xf1c0) this tag is used as a first argument for a complex expressions; e.g. ['lcsa', '<', 'operational']
   * - 'lcso'
     - Object Lifecycle State (it is part of the metadata, see the section above) this tag is used as a first argument for a complex expressions; e.g. ['lcso', '<', 'operational']
   * - 'conf'
     -
        - An action is permitted only if the host establishes the shielded connection with the chip using the specified Binding secret (e.g. 0xE140) and the response is requested with protection (encrypted).
        - Typical values are ['conf', 'e1', '40'] and ['conf', 'f1', 'd0'], where instead of 'f1', 'd0' can be used any properly configured Application Data Object
        - In the latter case (Secret in Application Data Object) it is recomended to use as well the 'int' (descrebed below) Access Condition
   * - 'int'
     -
        - An action is permitted only if the host establishes the shielded connection with the chip using the specified Binding secret (e.g. 0xE140) and the response is requested with protection (MAC).
        - Typical values are ['int', 'e1', '40'] and ['int', 'e0', 'ef'], where instead of 'e0', 'ef' can be used any properly configured Data Object of {'type': 'trust_anchor'}
        - In the latter case (Secret in Application Data Object) it is recomended to use as well the 'int' (descrebed below) Access Condition
        - Example ::

            ta_obj = Object(0xe0ef)
            ta_obj.meta = {'type': 'trust_anchor', 'read': 'always', 'change': ['lcso', '<', 'operational']}
            ta_obj.write(<X509 Certificate>)
            # This action is one-way and can't be reverted, for demo can be skipped
            # ta_obj.meta = {'lcso': 'operational'}
            protected_obj = Object(0xf1d0)
            protected_obj.meta = {'change': ['lcso', '<', 'operational', '&&', 'int', 'e0', 'ef']}
            # This action is one-way and can't be reverted, for demo can be skipped
            # protected_obj.meta = {'lcso': 'operational'}
            # The above means: in case of writing the f1d0 Application Data Object, the signature associated with the metadata
            # in the manifest must be verified with the addressed trust anchor e0ef.
   * - 'auto'
     -
       - An authorization reference Object ID. The action (for instance 'execute') is allowed only if the given object reached the AUTO (Authorised)
       - Typical values are ['auto', 'f1', 'd0']
   * - 'luc'
     -
   * - 'sec_sta_g'
     - x
   * - 'sec_sta_a'
     - x
   * - '=='
     - "If equal". Typical values ['lcso', **'=='**, 'initialiastion']
   * - '>'
     - "If more". Typical values ['lcso', **'>'**, 'initialiastion']
   * - '<'
     - "If less". Typical values ['lcso', **'<'**, 'initialiastion']
   * - '&&'
     - "And". Typical values ['lcso', **'<'**, 'initialiastion', **'&&'**, 'conf', 'e1', '40']
   * - '||'
     - "or". Typical values ['lcso', **'<'**, 'initialiastion', **'&&'**, 'conf', 'e1', '40']



Printing All metadata in human readable form
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