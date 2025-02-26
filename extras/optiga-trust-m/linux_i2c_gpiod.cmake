# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

if(UNIX)
	set(TARGET_I2C_SHLIB ${PROJECT_NAME}-i2c-gpiod-linux-${CMAKE_SYSTEM_PROCESSOR})

	set(TRUSTM_I2C_SRCS 
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_gpio_gpiod.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_i2c.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/target/gpiod/pal_ifx_i2c_config.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_os_event.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_os_datastore.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_logger.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_os_lock.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_os_timer.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_os_memory.c
		${TRUSTM_HOST_LIBRARY_PATH}/extras/pal/linux/pal_shared_mutex.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/optiga_comms_ifx_i2c.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_config.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_physical_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c
		${TRUSTM_HOST_LIBRARY_PATH}/src/comms/ifx_i2c/ifx_i2c_transport_layer.c
	)

	add_library(${TARGET_I2C_SHLIB} SHARED 
		${TRUSTM_I2C_SRCS}
		${TRUSTM_CORE_SRCS}
		${TRUSTM_HOST_LIBRARY_CORE_SRCS}
	)
	
	target_include_directories(${TARGET_I2C_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
		${TRUSTM_CONFIG_PATH}
		${TRUSTM_CORE_INC}
		${TRUSTM_HOST_LIBRARY_CORE_INC}
	)

	target_compile_definitions(${TARGET_I2C_SHLIB} PRIVATE  -DOPTIGA_USE_SOFT_RESET -DPAL_OS_HAS_EVENT_INIT -DHAS_LIBGPIOD)

	target_link_libraries(${TARGET_I2C_SHLIB} rt gpiod)

	set_target_properties( ${TARGET_I2C_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
		LIBRARY_OUTPUT_DIRECTORY ${TRUSTM_LIB_OUT_PATH}
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()