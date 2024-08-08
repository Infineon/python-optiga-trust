# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

if(UNIX)
	set(TARGET_UART_SHLIB ${PROJECT_NAME}-uart-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTM_UART_SRCS 
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/optiga_comms_tc_uart.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_os_event.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_gpio.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_config.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_os_datastore.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_logger.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_os_lock.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_os_timer.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux_uart/pal_os_memory.c   
	)

	add_library(${TARGET_UART_SHLIB} SHARED 
		${TRUSTM_UART_SRCS}
		${TRUSTM_CORE_SRCS}
		${TRUSTM_HOST_LIBRARY_CORE_SRCS}
	)

	target_include_directories(${TARGET_UART_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
		${TRUSTM_CONFIG_PATH}
		${TRUSTM_UART_INC}
		${TRUSTM_CORE_INC}
		${TRUSTM_HOST_LIBRARY_CORE_INC}
	)

	target_compile_definitions(${TARGET_UART_SHLIB} PRIVATE  -DOPTIGA_USE_SOFT_RESET -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_SYNC_COMMS)

	target_link_libraries(${TARGET_UART_SHLIB} rt)
	
	set_target_properties( ${TARGET_UART_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
		LIBRARY_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
