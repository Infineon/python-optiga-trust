# Build Instructions for the OPTIGA™ Trust M Host Library for C

To build the OPTIGA™ Trust Host Library for C as library, please check out the submodule in folder [extras/optiga-trust-m/](extras/optiga-trust-m/) as follows.

```bash
git submodule update --init
```

Precompiled libraries are available for the following platforms in [src/optigatrust/lib](../../src/optigatrust/lib/).

| OS      | Architecture | Interface | Library name                           |
| ------- | ------------ | --------- | -------------------------------------- |
| Linux   | armv7l       | I2C       | liboptigatrust-i2c-linux-armv7l.so     |
| Linux   | aarch64      | I2C       | liboptigatrust-i2c-linux-aarch64.so    |
| Linux   | x86_64       | I2C       | liboptigatrust-i2c-linux-x86_64.so     |
| Linux   | armv7l       | UART      | liboptigatrust-uart-linux-armv7l.so    |
| Linux   | aarch64      | UART      | liboptigatrust-uart-linux-aarch64.so   |
| Linux   | x86_64       | UART      | liboptigatrust-uart-linux-x86_64.so    |
| Linux   | armv7l       | LibUSB    | liboptigatrust-libusb-linux-armv7l.so  |
| Linux   | aarch64      | LibUSB    | liboptigatrust-libusb-linux-aarch64.so |
| Linux   | x86_64       | LibUSB    | liboptigatrust-libusb-linux-x86_64.so  |
| Windows | i686         | UART      | liboptigatrust-uart-win-x86_64.dll     |
| Windows | amd64        | UART      | liboptigatrust-uart-win-x86_64.dll     |
| Windows | i686         | LibUSB    | liboptigatrust-libsub-win-x86_64.dll   |
| Windows | amd64        | LibUSB    | liboptigatrust-libsub-win-x86_64.dll   |

## Linux

### Prerequesites

The Linux variant of the OPTIGA™ Trust M Host Library for C is based on [CMake](https://cmake.org/). CMake can be installed with the following command.

```bash
sudo apt-get install cmake
```

#### LibUSB variant

This project also support [LibUSB](https://libusb.info/) as an interface to the OPTIGA™ Trust M device. LibUSB can be installed with the following command.

```bash
sudo apt-get install libusb-1.0-0-dev
```

### Building

To build the library from this folder (`extras/optiga-trust-m`), run the following commands. You can enable/disable the build of individual interfaces via `-D<variant>=ON`.

```bash
cmake -B build -Di2c=ON -Duart=ON -Dlibusb=ON
cmake --build build
```

#### Example output
<details>
<summary>
Sample output
</summary>

```bash
$ cmake -B build
-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is GNU 11.4.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: ./extras/optiga-trust-m/build

$ cmake --build build
[  1%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal.c.o
[  3%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_gpio.c.o
[  4%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_i2c.c.o
[  6%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/target/rpi3/pal_ifx_i2c_config.c.o
[  7%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_os_event.c.o
[  9%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_os_datastore.c.o
[ 10%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_logger.c.o
[ 12%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_os_lock.c.o
[ 13%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_os_timer.c.o
[ 15%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/extras/pal/linux/pal_os_memory.c.o
[ 16%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/optiga_comms_ifx_i2c.c.o
[ 18%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c.c.o
[ 20%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_config.c.o
[ 21%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
[ 23%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
[ 24%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c.o
[ 26%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
[ 27%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/src/optiga_trust_init.c.o
[ 29%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/crypt/optiga_crypt.c.o
[ 30%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/util/optiga_util.c.o
[ 32%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/cmd/optiga_cmd.c.o
[ 33%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/common/optiga_lib_common.c.o
[ 35%] Building C object CMakeFiles/optigatrust-i2c-linux-x86_64.dir/external/optiga/src/common/optiga_lib_logger.c.o
[ 36%] Linking C shared library /home/mspaehn/SW/Python/python-optiga-trust-rework/src/optigatrust/lib/liboptigatrust-i2c-linux-x86_64.so
[ 36%] Built target optigatrust-i2c-linux-x86_64
[ 38%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal.c.o
[ 40%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_common.c.o
[ 41%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_gpio.c.o
[ 43%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_i2c.c.o
[ 44%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_ifx_usb_config.c.o
[ 46%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_os_event.c.o
[ 47%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_logger.c.o
[ 49%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_os_datastore.c.o
[ 50%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_os_lock.c.o
[ 52%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_os_memory.c.o
[ 53%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/extras/pal/libusb/pal_os_timer.c.o
[ 55%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/optiga_comms_ifx_i2c.c.o
[ 56%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c.c.o
[ 58%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_config.c.o
[ 60%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
[ 61%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
[ 63%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c.o
[ 64%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
[ 66%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/src/optiga_trust_init.c.o
[ 67%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/crypt/optiga_crypt.c.o
[ 69%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/util/optiga_util.c.o
[ 70%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/cmd/optiga_cmd.c.o
[ 72%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/common/optiga_lib_common.c.o
[ 73%] Building C object CMakeFiles/optigatrust-libusb-linux-x86_64.dir/external/optiga/src/common/optiga_lib_logger.c.o
[ 75%] Linking C shared library /home/mspaehn/SW/Python/python-optiga-trust-rework/src/optigatrust/lib/liboptigatrust-libusb-linux-x86_64.so
[ 75%] Built target optigatrust-libusb-linux-x86_64
[ 76%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/optiga_comms_tc_uart.c.o
[ 78%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_os_event.c.o
[ 80%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_gpio.c.o
[ 81%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_config.c.o
[ 83%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_os_datastore.c.o
[ 84%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_logger.c.o
[ 86%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_os_lock.c.o
[ 87%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_os_timer.c.o
[ 89%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/extras/pal/linux_uart/pal_os_memory.c.o
[ 90%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/src/optiga_trust_init.c.o
[ 92%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/src/crypt/optiga_crypt.c.o
[ 93%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/src/util/optiga_util.c.o
[ 95%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/src/cmd/optiga_cmd.c.o
[ 96%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/src/common/optiga_lib_common.c.o
[ 98%] Building C object CMakeFiles/optigatrust-uart-linux-x86_64.dir/external/optiga/src/common/optiga_lib_logger.c.o
[100%] Linking C shared library /home/mspaehn/SW/Python/python-optiga-trust-rework/src/optigatrust/lib/liboptigatrust-uart-linux-x86_64.so
[100%] Built target optigatrust-uart-linux-x86_64
```
</details>

## Windows

### Prerequesites

For building the OPTIGA™ Trust M Host Library for C on Windows, Microsoft Visual Studio is needed. Currently, this project is tested with Microsoft Visual Studio 2022.

#### LibUSB variant

This project also support [LibUSB](https://libusb.info/) as an interface to the OPTIGA™ Trust M device. The needed header files and static libraries for LibUSB can be installed with the following batch script: [download_libusb_windows.bat](download_libusb_windows.bat)

## Integrate OPTIGA™ Trust M Host Library for C into the Python module

To integrate your freshly compiled version of the OPTIGA™ Trust M Host Library for C into the Python module, please follow the steps in the main [README.md](../../README.md).