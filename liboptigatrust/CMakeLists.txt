cmake_minimum_required(VERSION 2.6.4)
project(liboptigatrust)

# BUILD Options
option(TRUST_PAL_LIBUSB  "Add support for the HID enabled OPTIGA(TM) Trust") # e.g. Perso2Go Board
option(TRUST_PAL_RPI3 "Add support for the direct communication over I2C -- for RPi3")
option(TRUST_BUILD_SHARED_LIBS "Build as a shared library" ON)
set(BUILD_SHARED_LIBS ${OPTIGA_TRUST_BUILD_SHARED_LIBS})

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
)
	
if(TRUST_PAL_LIBUSB AND LINUX)
	find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
	find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
	find_library(HAS_LIBUSB usb-1.0)
	if(NOT HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
		message(FATAL_ERROR, "Missing Build Dependencies for TRUST_PAL_LIBUSB - install libusb-1.0-0-dev")
	endif()
else()
	set(LIBUSD_INCLUDE_DIR "")
endif()

if(TRUST_PAL_LIBUSB)
	file(GLOB TRUST_PAL_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pal/libusb/*.c")
	set(TRUST_PAL_INC ${TRUST_PAL_INC} pal/libusb/include)
	add_definitions(-DUSE_LIBUSB_PAL)
endif()

if(TRUST_PAL_RPI3)
	file(GLOB TRUST_PAL_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pal/linux/target/rpi3/*.c")
	set(TRUST_PAL_SRCS ${TRUST_PAL_SRCS} pal/linux/target/rpi3/pal_ifx_i2c_config.c)
	set(TRUST_PAL_INC ${TRUST_PAL_INC} pal/linux/target/rpi3)
endif(TRUST_PAL_RPI3)

add_library(${PROJECT_NAME} SHARED ${TRUST_CORE_SRCS} ${TRUST_PAL_SRCS})
include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
											optiga/include
											${LIBUSB_INCLUDE_DIR}
											${TRUST_PAL_INC})
if(LINUX)
	if(HAS_LIBUSB AND TRUST_PAL_LIBUSB)
		target_link_libraries(${PROJECT_NAME} usb-1.0)
	endif()
target_link_libraries(${PROJECT_NAME} rt)
endif()

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/library
    PUBLIC_HEADER DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/library)


