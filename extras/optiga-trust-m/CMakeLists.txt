# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.5)
include(GNUInstallDirs)
project(optigatrust)

set(TRUSTM_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(TRUSTM_LIB_OUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../src/optigatrust/lib)
set(TRUSTM_HOST_LIBRARY_PATH ${TRUSTM_PATH}/external/optiga)

add_compile_definitions(OPTIGA_LIB_EXTERNAL="optiga_lib_config_m_v3_python.h")
set(TRUSTM_CONFIG_PATH ${TRUSTM_PATH}/config)

# Add sources for Trust M Core and Platform Abstraction Layer
set(TRUSTM_CORE_SRCS 
    ${TRUSTM_PATH}/src/optiga_trust_init.c
)

set(TRUSTM_CORE_INC
    ${TRUSTM_PATH}/include
)

set(TRUSTM_HOST_LIBRARY_CORE_SRCS 
    ${TRUSTM_HOST_LIBRARY_PATH}/src/crypt/optiga_crypt.c
    ${TRUSTM_HOST_LIBRARY_PATH}/src/util/optiga_util.c
    ${TRUSTM_HOST_LIBRARY_PATH}/src/cmd/optiga_cmd.c
    ${TRUSTM_HOST_LIBRARY_PATH}/src/common/optiga_lib_common.c
    ${TRUSTM_HOST_LIBRARY_PATH}/src/common/optiga_lib_logger.c
)

set(TRUSTM_HOST_LIBRARY_CORE_INC
    ${TRUSTM_HOST_LIBRARY_PATH}/include
    ${TRUSTM_HOST_LIBRARY_PATH}/include/cmd
    ${TRUSTM_HOST_LIBRARY_PATH}/include/common
    ${TRUSTM_HOST_LIBRARY_PATH}/include/comms
    ${TRUSTM_HOST_LIBRARY_PATH}/include/ifx_i2c
    ${TRUSTM_HOST_LIBRARY_PATH}/include/pal
)

# Select build variant (e.g. use cmake -Duart=ON -Di2c=ON -Dlibusb=ON)
if(i2c)
    include(${TRUSTM_PATH}/linux_i2c.cmake)
endif(i2c)

if(libusb)
    include(${TRUSTM_PATH}/linux_libusb.cmake)
endif(libusb)

if(uart)
    include(${TRUSTM_PATH}/linux_uart.cmake)
endif(uart)
