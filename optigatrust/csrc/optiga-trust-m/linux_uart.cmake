if(UNIX)
	set(TARGET_UART_SHLIB ${PROJECT_NAME}-uart-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTM_UART_SRCS 
		${TRUSTM_PATH}/pal/transparent_channel_linux/optiga_comms_tc_uart.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_os_event.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_i2c.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_gpio.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_config.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_os_datastore.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_logger.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_os_lock.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_os_timer.c
		${TRUSTM_PATH}/pal/transparent_channel_linux/pal_os_memory.c   
	)
	set(TRUSTM_UART_INC ${TRUSTM_PATH}/pal/transparent_channel_linux)
	add_library(${TARGET_UART_SHLIB} SHARED ${TRUSTM_CORE_SRCS} ${TRUSTM_UART_SRCS})
	target_include_directories(${TARGET_UART_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
													   ${TRUSTM_PATH}/optiga/include
													   ${TRUSTM_UART_INC})
	target_compile_definitions(${TARGET_UART_SHLIB} PRIVATE  -DOPTIGA_USE_SOFT_RESET -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_SYNC_COMMS)
	target_link_libraries(${TARGET_UART_SHLIB} rt)
	set_target_properties( ${TARGET_UART_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
