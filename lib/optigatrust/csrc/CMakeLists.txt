cmake_minimum_required(VERSION 2.6.4)
project(optigatrust)

# BUILD Options
option(TRUST_PAL_LIBUSB "Add support for the HID enabled OPTIGA(TM) Trust" ON) # e.g. Perso2Go Board
option(TRUST_PAL_RPI3 "Add support for the direct communication over I2C -- for RPi3")
option(TRUST_BUILD_SHARED_LIBS "Build as a shared library" ON)
set(BUILD_SHARED_LIBS ${OPTIGA_TRUST_BUILD_SHARED_LIBS})
	
# Check for required Libraries
if(TRUST_PAL_LIBUSB AND UNIX)
	find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
	find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
	find_library(HAS_LIBUSB usb-1.0)
	if(NOT HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
		message(FATAL_ERROR, "Missing Build Dependencies for TRUST_PAL_LIBUSB - install libusb-1.0-0-dev")	
	endif()
else()
	set(LIBUSD_INCLUDE_DIR "")
endif()

# Add sources for Trust Core and Platform Abstraction Layer
# Add sources
set(TRUST_CORE_SRCS 
    optiga-trust-x/optiga/crypt/optiga_crypt.c
    optiga-trust-x/optiga/util/optiga_util.c
    optiga-trust-x/optiga/cmd/CommandLib.c
    optiga-trust-x/optiga/common/Logger.c
    optiga-trust-x/optiga/common/Util.c
    optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c.c
    optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_config.c
    optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
    optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
    optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
    optiga-trust-x/optiga/dtls/AlertProtocol.c
    optiga-trust-x/optiga/dtls/DtlsFlightHandler.c
    optiga-trust-x/optiga/dtls/DtlsHandshakeProtocol.c
    optiga-trust-x/optiga/dtls/DtlsRecordLayer.c
    optiga-trust-x/optiga/dtls/DtlsTransportLayer.c
    optiga-trust-x/optiga/dtls/DtlsWindowing.c
    optiga-trust-x/optiga/dtls/HardwareCrypto.c
    optiga-trust-x/optiga/dtls/MessageLayer.c
    optiga-trust-x/optiga/dtls/OCP.c
    optiga-trust-x/optiga/dtls/OCPConfig.c
    optiga_trust_init.c
)

if(TRUST_PAL_LIBUSB)
    set(TRUST_PAL_SRCS 
        optiga-trust-x/pal/libusb/optiga_comms_ifx_i2c_usb.c
        optiga-trust-x/pal/libusb/pal_common.c
        optiga-trust-x/pal/libusb/pal.c
	optiga-trust-x/pal/libusb/pal_gpio.c
	optiga-trust-x/pal/libusb/pal_i2c.c
	optiga-trust-x/pal/libusb/pal_ifx_usb_config.c
	optiga-trust-x/pal/libusb/pal_os_event.c
	optiga-trust-x/pal/libusb/pal_os_lock.c
	optiga-trust-x/pal/libusb/pal_os_timer.c   
    )
    set(TRUST_PAL_INC ${TRUST_PAL_INC} optiga-trust-x/pal/libusb/include)
    add_definitions(-DUSE_LIBUSB_PAL -DPAL_OS_HAS_EVENT_INIT)
endif()

if(TRUST_PAL_RPI3)
    set(TRUST_PAL_SRCS 
        optiga-trust-x/pal/linux/optiga_comms.c
        optiga-trust-x/pal/linux/pal.c
	optiga-trust-x/pal/linux/pal_gpio.c
	optiga-trust-x/pal/linux/pal_i2c.c
	optiga-trust-x/pal/linux/pal_ifx_i2c_config.c
	optiga-trust-x/pal/linux/pal_os_event.c
	optiga-trust-x/pal/linux/pal_os_lock.c
	optiga-trust-x/pal/linux/pal_os_timer.c   
    )
    set(TRUST_PAL_INC ${TRUST_PAL_INC} optiga-trust-x/pal/linux/target/rpi3)
endif(TRUST_PAL_RPI3)

add_library(${PROJECT_NAME} SHARED ${TRUST_CORE_SRCS} ${TRUST_PAL_SRCS})
include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
                                           optiga-trust-x/optiga/include
                                           ${LIBUSB_INCLUDE_DIR}
                                           ${TRUST_PAL_INC})
if(UNIX)
	if(HAS_LIBUSB AND TRUST_PAL_LIBUSB)
		target_link_libraries(${PROJECT_NAME} usb-1.0)
	endif()
	target_link_libraries(${PROJECT_NAME} rt)
endif()

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/library/${CMAKE_HOST_SYSTEM_PROCESSOR}
    PUBLIC_HEADER DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/library/${CMAKE_HOST_SYSTEM_PROCESSOR})
