# Check for required Libraries
if(UNIX)
	find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
	find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
	find_library(HAS_LIBUSB usb-1.0)
	if(NOT HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
		message(FATAL_ERROR, "Missing Build Dependencies for TRUST_PAL_LIBUSB - install libusb-1.0-0-dev")	
	endif()

	set(TARGET_LIBUSB_SHLIB ${PROJECT_NAME}-libusb-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTX_LIBUSB_SRCS 
		${TRUSTX_PATH}/pal/libusb/optiga_comms_ifx_i2c_usb.c
		${TRUSTX_PATH}/pal/libusb/pal_common.c
		${TRUSTX_PATH}/pal/libusb/pal.c
		${TRUSTX_PATH}/pal/libusb/pal_gpio.c
		${TRUSTX_PATH}/pal/libusb/pal_i2c.c
		${TRUSTX_PATH}/pal/libusb/pal_ifx_usb_config.c
		${TRUSTX_PATH}/pal/libusb/pal_os_event.c
		${TRUSTX_PATH}/pal/libusb/pal_os_lock.c
		${TRUSTX_PATH}/pal/libusb/pal_os_timer.c   
	)
	set(TRUSTX_LIBUSB_INC ${TRUSTX_PATH}/pal/libusb/include)
	add_library(${TARGET_LIBUSB_SHLIB} SHARED ${TRUSTX_CORE_SRCS} ${TRUSTX_LIBUSB_SRCS})
	target_include_directories(${TARGET_LIBUSB_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
													   ${TRUSTX_PATH}/optiga/include
													   ${LIBUSB_INCLUDE_DIR}
													   ${TRUSTX_LIBUSB_INC})
	target_compile_definitions(${TARGET_LIBUSB_SHLIB} PRIVATE  -DUSE_LIBUSB_PAL -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_USE_SOFT_RESET)
	if(HAS_LIBUSB)
		target_link_libraries(${TARGET_LIBUSB_SHLIB} usb-1.0)
	endif(HAS_LIBUSB)
	target_link_libraries(${TARGET_LIBUSB_SHLIB} rt)

	set_target_properties( ${TARGET_LIBUSB_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()