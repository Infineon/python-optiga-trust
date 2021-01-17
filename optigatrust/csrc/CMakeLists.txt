cmake_minimum_required(VERSION 3.5)
include(GNUInstallDirs)
project(optigatrust)

if(FALSE) # a block comment

set(TRUSTX_PATH optiga-trust-x)

# Add sources for Trust X Core and Platform Abstraction Layer
# Add sources
set(TRUSTX_CORE_SRCS 
    ${TRUSTX_PATH}/optiga/crypt/optiga_crypt.c
    ${TRUSTX_PATH}/optiga/util/optiga_util.c
    ${TRUSTX_PATH}/optiga/cmd/CommandLib.c
    ${TRUSTX_PATH}/optiga/common/Logger.c
    ${TRUSTX_PATH}/optiga/common/Util.c
    ${TRUSTX_PATH}/optiga/comms/ifx_i2c/ifx_i2c.c
    ${TRUSTX_PATH}/optiga/comms/ifx_i2c/ifx_i2c_config.c
    ${TRUSTX_PATH}/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
    ${TRUSTX_PATH}/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
    ${TRUSTX_PATH}/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
    ${TRUSTX_PATH}/optiga/dtls/AlertProtocol.c
    ${TRUSTX_PATH}/optiga/dtls/DtlsFlightHandler.c
    ${TRUSTX_PATH}/optiga/dtls/DtlsHandshakeProtocol.c
    ${TRUSTX_PATH}/optiga/dtls/DtlsRecordLayer.c
    ${TRUSTX_PATH}/optiga/dtls/DtlsTransportLayer.c
    ${TRUSTX_PATH}/optiga/dtls/DtlsWindowing.c
    ${TRUSTX_PATH}/optiga/dtls/HardwareCrypto.c
    ${TRUSTX_PATH}/optiga/dtls/MessageLayer.c
    ${TRUSTX_PATH}/optiga/dtls/OCP.c
    ${TRUSTX_PATH}/optiga/dtls/OCPConfig.c
    ${TRUSTX_PATH}/optiga_trust_init.c
)

include(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTX_PATH}/linux_i2c.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTX_PATH}/linux_libusb.cmake)

else()

set(TRUSTM_PATH optiga-trust-m)

# Add sources for Trust M Core and Platform Abstraction Layer
# Add sources
set(TRUSTM_CORE_SRCS 
    ${TRUSTM_PATH}/optiga/crypt/optiga_crypt.c
    ${TRUSTM_PATH}/optiga/util/optiga_util.c
    ${TRUSTM_PATH}/optiga/cmd/optiga_cmd.c
    ${TRUSTM_PATH}/optiga/common/optiga_lib_common.c
    ${TRUSTM_PATH}/optiga/common/optiga_lib_logger.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_config.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
	${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_presentation_layer.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
	${TRUSTM_PATH}/optiga/comms/optiga_comms_ifx_i2c.c
    ${TRUSTM_PATH}/optiga_trust_init.c
)

include(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/linux_i2c.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/linux_libusb.cmake)

endif()