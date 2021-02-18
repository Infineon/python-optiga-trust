Enable the provisioning mode on your Evaluation Kit
---------------------------------------------------

OPTIGA™ Trust M Evaluation Kit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


OPTIGA™ Trust Charge Evaluation Kit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- Make sure you have connected your Evaluation Kit as depicted below (USB Port **X1002**)

.. image:: https://raw.githubusercontent.com/Infineon/Assets/master/Pictures/optiga_trust_charge_evalkit_debug_mode.jpg

- Make usre you have Segger J-Link tool v6.00 installed. J-Link tool `Download for Windows, Linux, Mac`_
- Click on **Device** to select a target device: Select Infineon as Manufacturer
- Run JFlashLite.exe from JLink installation folder. It shows a notice window. Click OK.
- Select Infineon as Manufacturer and Device as XMC4700-2048, and then click OK.
- Select `hex file`_ to be flashed under **Data File** and click on **Program Device**. It then shows the programming progress window.
- Once done make sure to change the connection of the USB cable to a differt USB port located on the other side of the Evaluation Kit (USB Port **X100**)

.. image:: https://raw.githubusercontent.com/Infineon/Assets/master/Pictures/optiga_trust_charge_evalkit_provisioning_mode.jpg



.. _Download for Windows, Linux, Mac: https://www.segger.com/downloads/jlink/#J-LinkSoftwareAndDocumentationPack
.. _hex file: _static/optiga_trust_charge_evalkit_uart_python.hex