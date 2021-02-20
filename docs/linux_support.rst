Porting to non-Raspberry Linux
------------------------------

The SDK uses a shared library to connect to the chip over the i2c device.
The SDk is  comes with a shared library compiled for Raspberry Pi3 (armv7l) which uses in the end /dev/i2c-1 device to access the Security Chip.

If the default library doesn't work for your setup or architecture, you might need to build the shared library for your platform.

For this you need to have `cmake` and `build-essential` packages installed in your system.
Additionally, if you have OPTIGA connected to other than /dev/i2c-1 device, you might need to change this value here_ before you continue with other steps

Then you can do the following::


	pi@pi:/home/pi/git$ git clone https://github.com/Infineon/python-optiga-trust
	pi@pi:/home/pi/git$ cd python-optiga-trust/optigatrust/csrc
	pi@pi:/home/pi/git/python-optiga-trust/optigatrust/csrc$ mkdir build && cd build
	pi@pi:/home/pi/git/python-optiga-trust/optigatrust/csrc/build$ cmake ..
	pi@pi:/home/pi/git/python-optiga-trust/optigatrust/csrc/build$ make
	Scanning dependencies of target optigatrust-libusb-linux-armv7l
	[  1%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/crypt/optiga_crypt.c.o
	[  3%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/util/optiga_util.c.o
	[  4%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/cmd/CommandLib.c.o
	[  6%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/common/Logger.c.o
	[  8%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/common/Util.c.o
	[  9%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c.c.o
	[ 11%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_config.c.o
	[ 13%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
	[ 14%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
	[ 16%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
	[ 18%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/AlertProtocol.c.o
	[ 19%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsFlightHandler.c.o
	[ 21%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsHandshakeProtocol.c.o
	[ 22%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsRecordLayer.c.o
	[ 24%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsTransportLayer.c.o
	[ 26%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsWindowing.c.o
	[ 27%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/HardwareCrypto.c.o
	[ 29%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/MessageLayer.c.o
	[ 31%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCP.c.o
	[ 32%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCPConfig.c.o
	[ 34%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga_trust_init.c.o
	[ 36%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/optiga_comms_ifx_i2c_usb.c.o
	[ 37%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_common.c.o
	[ 39%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal.c.o
	[ 40%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_gpio.c.o
	[ 42%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_i2c.c.o
	[ 44%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_ifx_usb_config.c.o
	[ 45%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_event.c.o
	[ 47%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_lock.c.o
	[ 49%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_timer.c.o
	[ 50%] Linking C shared library ../lib/liboptigatrust-libusb-linux-armv7l.so
	[ 50%] Built target optigatrust-libusb-linux-armv7l
	Scanning dependencies of target optigatrust-i2c-linux-armv7l
	[ 52%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/crypt/optiga_crypt.c.o
	[ 54%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/util/optiga_util.c.o
	[ 55%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/cmd/CommandLib.c.o
	[ 57%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/common/Logger.c.o
	[ 59%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/common/Util.c.o
	[ 60%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c.c.o
	[ 62%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_config.c.o
	[ 63%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
	[ 65%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
	[ 67%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
	[ 68%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/AlertProtocol.c.o
	[ 70%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsFlightHandler.c.o
	[ 72%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsHandshakeProtocol.c.o
	[ 73%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsRecordLayer.c.o
	[ 75%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsTransportLayer.c.o
	[ 77%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsWindowing.c.o
	[ 78%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/HardwareCrypto.c.o
	[ 80%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/MessageLayer.c.o
	[ 81%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCP.c.o
	[ 83%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCPConfig.c.o
	[ 85%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga_trust_init.c.o
	[ 86%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/optiga_comms.c.o
	[ 88%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal.c.o
	[ 90%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_gpio.c.o
	[ 91%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_i2c.c.o
	[ 93%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/target/rpi3/pal_ifx_i2c_config.c.o
	[ 95%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_event.c.o
	[ 96%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_lock.c.o
	[ 98%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_timer.c.o
	[100%] Linking C shared library ../lib/liboptigatrust-i2c-linux-armv7l.so
	[100%] Built target optigatrust-i2c-linux-armv7l
	pi@pi:/home/pi/git/python-optiga-trust/optigatrust/csrc/build$ cd ../../../
	pi@pi:/home/pi/git/python-optiga-trust$ pip install .



.. _here: https://github.com/Infineon/python-optiga-trust/blob/af928b9aa19b7c0174d1230628c52c781073beee/optigatrust/csrc/optiga-trust-m/pal/linux/pal_i2c.c#L53