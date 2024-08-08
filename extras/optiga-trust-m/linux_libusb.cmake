# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

if(UNIX)
	# Check for required Libraries
	find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
	find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
	find_library(HAS_LIBUSB usb-1.0)
	if(NOT HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
		message(FATAL_ERROR, "Missing Build Dependencies for TRUST_PAL_LIBUSB - install libusb-1.0-0-dev")	
	endif()

	set(TARGET_LIBUSB_SHLIB ${PROJECT_NAME}-libusb-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTM_LIBUSB_SRCS
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_common.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_gpio.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_i2c.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_ifx_usb_config.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_os_event.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_logger.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_os_datastore.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_os_lock.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_os_memory.c  
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/pal_os_timer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/optiga_comms_ifx_i2c.c 
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_config.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_physical_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_transport_layer.c
	)

	set(TRUSTM_LIBUSB_INC 
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/libusb/include
	)

	add_library(${TARGET_LIBUSB_SHLIB} SHARED 
		${TRUSTM_LIBUSB_SRCS}
		${TRUSTM_CORE_SRCS}
		${TRUSTM_HOST_LIBRARY_CORE_SRCS}
	)

	target_include_directories(${TARGET_LIBUSB_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
		${TRUSTM_CONFIG_PATH}
		${TRUSTM_LIBUSB_INC}
		${TRUSTM_CORE_INC}
		${TRUSTM_HOST_LIBRARY_CORE_INC}
	)

	target_compile_definitions(${TARGET_LIBUSB_SHLIB} PRIVATE  -DIFX_I2C_FRAME_SIZE=55 -DUSE_LIBUSB_PAL -DPAL_OS_HAS_EVENT_INIT)

	if(HAS_LIBUSB)
		target_link_libraries(${TARGET_LIBUSB_SHLIB} usb-1.0)
	endif(HAS_LIBUSB)

	target_link_libraries(${TARGET_LIBUSB_SHLIB} rt)

	set_target_properties( ${TARGET_LIBUSB_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
		LIBRARY_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
