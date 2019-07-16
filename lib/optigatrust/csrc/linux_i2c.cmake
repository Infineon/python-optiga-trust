if(UNIX)

	set(TARGET_I2C_SHLIB ${PROJECT_NAME}-i2c-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTX_I2C_SRCS 
		${TRUSTX_PATH}/optiga/comms/optiga_comms.c
		${TRUSTX_PATH}/pal/linux/pal.c
		${TRUSTX_PATH}/pal/linux/pal_gpio.c
		${TRUSTX_PATH}/pal/linux/pal_i2c.c
		${TRUSTX_PATH}/pal/linux/target/rpi3/pal_ifx_i2c_config.c
		${TRUSTX_PATH}/pal/linux/pal_os_event.c
		${TRUSTX_PATH}/pal/linux/pal_os_lock.c
		${TRUSTX_PATH}/pal/linux/pal_os_timer.c   
	)
	set(TRUSTX_I2C_INC ${TRUSTX_PATH}/pal/linux)
	add_library(${TARGET_I2C_SHLIB} SHARED ${TRUSTX_CORE_SRCS} ${TRUSTX_I2C_SRCS})
	target_include_directories(${TARGET_I2C_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
													   ${TRUSTX_PATH}/optiga/include
													   ${TRUSTX_I2C_INC})
	target_compile_definitions(${TARGET_I2C_SHLIB} PRIVATE  -DOPTIGA_USE_SOFT_RESET -DPAL_OS_HAS_EVENT_INIT)
	target_link_libraries(${TARGET_I2C_SHLIB} rt)
	set_target_properties( ${TARGET_I2C_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()