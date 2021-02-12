#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "optiga\comms\optiga_comms.h"


#define MAX_TRANSMIT_FRAME_SIZE			(2000-2)
#define CONFIG_FILE_NAME	 "optiga_comms.ini" 

typedef struct com_context
{
	HANDLE com_handle;
	char * com_port;
	char *path;
}com_context_t;


com_context_t com_context = {0};

static optiga_lib_status_t _optiga_comms_get_params(com_context_t * p_com_ctx, char *path)
{
	optiga_lib_status_t return_status = OPTIGA_COMMS_ERROR;
	FILE *pConfigFile = NULL;
	uint8_t string_length;
	char file_path[1000];
	char szConfig[50];
	char *file_name = CONFIG_FILE_NAME;
	char comport[20] = "\\\\.\\";

	do
	{
		//read xml file from current location
		strcpy(file_path, path);
		strcat(file_path, file_name);
		//Read configuration file
		pConfigFile = fopen(file_path, "r");
		if (NULL == pConfigFile)
		{
			printf("\n!!!Unable to open %s\n", CONFIG_FILE_NAME);
			break;
		}

		if (NULL == fgets(szConfig, sizeof(szConfig), pConfigFile))
		{
			printf("\n!!!Unable to read %s\n", CONFIG_FILE_NAME);
			break;
		}
		string_length = strlen(szConfig);
		if (string_length  > 4)
		{
			strcat(comport,szConfig);
			//printf ("\nData read from file \n%s\n Length = %d", comport, strlen(comport));
			strcpy((char *)p_com_ctx->com_port, comport);
		}
		else
		{
			//printf ("\nData read from file \n%s\n Length = %d", szConfig, strlen(szConfig));
			strcpy((char *)p_com_ctx->com_port, szConfig);
		}

		return_status = OPTIGA_COMMS_SUCCESS;
	} while (0);

	if (NULL != pConfigFile)
	{
		fclose(pConfigFile);
	}
}

optiga_lib_status_t optiga_comms_set_callback_handler(optiga_comms_t * p_optiga_comms, callback_handler_t handler)
{
	p_optiga_comms->upper_layer_handler = handler;
	return (0);
}

optiga_lib_status_t optiga_comms_set_callback_context(optiga_comms_t * p_optiga_comms, void * context)
{
	p_optiga_comms->p_upper_layer_ctx = context;
	return (0);
}


optiga_comms_t * optiga_comms_create(callback_handler_t callback, void * context)
{
	optiga_comms_t * p_optiga_comms = (optiga_comms_t *)calloc(sizeof(optiga_comms_t), 1);
	p_optiga_comms->p_comms_ctx = &com_context;
	return (p_optiga_comms);
}

void optiga_comms_destroy(optiga_comms_t * p_ctx)
{
#define COMM_CTX	((com_context_t * )(p_ctx->p_comms_ctx))
	if (NULL != p_ctx)
	{
		free(p_ctx);
	}
#undef COMM_CTX
}
/**
*  \brief This API open the communication channel.
*
* \details
*  - This api opens the COM port based on the input provided in optiga_comms.ini file
* \param[in,out] p_ctx        Pointer to #optiga_comms_t
*
* \retval  #OPTIGA_COMMS_SUCCESS
* \retval  #OPTIGA_COMMS_ERROR
*/
optiga_lib_status_t optiga_comms_open(optiga_comms_t * p_ctx)
{
	com_context_t * p_comms_context = (com_context_t *)(p_ctx->p_comms_ctx);
	optiga_lib_status_t api_status = OPTIGA_COMMS_ERROR;
	DWORD last_error = 0;
	DCB dcbSerialParams = { 0 };
	COMMTIMEOUTS timeouts = { 0 };

	p_comms_context->com_port = (char *)calloc(10, 1);
	_optiga_comms_get_params((com_context_t *)p_ctx->p_comms_ctx, p_ctx->path);

	com_context.com_handle = CreateFile(com_context.com_port, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == p_comms_context->com_handle)
	{
		last_error = GetLastError();
		printf("\n!!!Error in opening serial port : %d", last_error);
	}
	else
	{
		dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
		GetCommState(p_comms_context->com_handle, &dcbSerialParams);

		//!!CONFIG!!
		dcbSerialParams.BaudRate = CBR_115200;
		dcbSerialParams.ByteSize = 8;
		dcbSerialParams.StopBits = ONESTOPBIT;
		dcbSerialParams.Parity = NOPARITY;

		SetCommState(p_comms_context->com_handle, &dcbSerialParams);
		
		timeouts.ReadIntervalTimeout = 50;
		timeouts.ReadTotalTimeoutConstant = 50;
		timeouts.ReadTotalTimeoutMultiplier = 10;
		timeouts.WriteTotalTimeoutConstant = 50;
		timeouts.WriteTotalTimeoutMultiplier = 10;

		api_status = OPTIGA_COMMS_SUCCESS;
		//printf("Serial port %s opened\n", com_context.com_port);
	}

	return api_status;
}

/**
*  \brief This API resets the OPTIGA.
*
* \param[in,out] p_ctx        Pointer to #optiga_comms_t
* \param[in,out] reset_type   type of reset
*
* \retval  #OPTIGA_COMMS_SUCCESS
* \retval  #OPTIGA_COMMS_ERROR
*/
optiga_lib_status_t optiga_comms_reset(optiga_comms_t *p_ctx, uint8_t reset_type)
{
	optiga_lib_status_t api_status = OPTIGA_COMMS_ERROR;

	return api_status;
}

/**
 * \brief   This API sends a command and receives a response.
 *
 * \details
 *  - Total number of bytes transmit as MAX_TRANSMIT_FRAME_SIZE - 2.
 *  - If the data size is less then (MAX_TRANSMIT_FRAME_SIZE - 2) its prepend garbage value and actual length is captured in first 2 bytes
 *  - While receiving data its check for the first 2 bytes for length o actual data to be processes.
 *  - Received data is 2 byte and the value is 0xFF 0xFF the api returns #OPTIGA_COMMS_ERROR.
 *
 * \param[in,out] p_ctx              Pointer to #optiga_comms_t
 * \param[in]     p_tx_data          Pointer to the write data buffer
 * \param[in]     tx_data_length     Pointer to the length of the write data buffer
 * \param[in,out] p_rx_data          Pointer to the receive data buffer
 * \param[in,out] p_rx_data_len      Pointer to the length of the receive data buffer
 *
 * \retval  #OPTIGA_COMMS_SUCCESS
 * \retval  #OPTIGA_COMMS_ERROR
*/
optiga_lib_status_t optiga_comms_transceive(optiga_comms_t * p_ctx,
											const uint8_t * p_tx_data,
											uint16_t tx_data_length,
											uint8_t * p_rx_data,
											uint16_t * p_rx_data_len)
{
	com_context_t * COMM_CTX = (com_context_t *)(p_ctx->p_comms_ctx);
	optiga_lib_status_t api_status = OPTIGA_COMMS_ERROR;
	BOOL bool_status;

	uint32_t number_of_bytes_written = 0;
	uint8_t byte_of_data[MAX_TRANSMIT_FRAME_SIZE] = {0};
	uint32_t NoBytesRead;
	uint32_t index = 0;
	uint8_t failure_status[] = {0xff,0xff}; 
	uint8_t max_transmit_frame[MAX_TRANSMIT_FRAME_SIZE];

	do
	{
		/*printf ("\ntransceive : send length %d\n", tx_data_length);
		for (int i = 0; i < tx_data_length; i++)
			printf("%02X:", p_tx_data[i]);
		printf("\n");*/
		// Form data frame : [tx_data_length byte 1][tx_data_length byte 2][copied p_tx_data which is less than MAX_TRANSMIT_FRAME_SIZE]
		max_transmit_frame[0] = (uint8_t)(tx_data_length >> 8);
		max_transmit_frame[1] = (uint8_t)(tx_data_length);
		memcpy(max_transmit_frame + 2, p_tx_data, tx_data_length);

		//Write Data
		bool_status = WriteFile(COMM_CTX->com_handle, max_transmit_frame, MAX_TRANSMIT_FRAME_SIZE, (LPDWORD)&number_of_bytes_written, NULL);
		if (0 == bool_status)
		{
			printf ("\n!!!COM port write failed");
			printf("Error is %d", GetLastError());
			break;
		}

		bool_status = ReadFile(COMM_CTX->com_handle, &byte_of_data, MAX_TRANSMIT_FRAME_SIZE, (LPDWORD)&NoBytesRead, NULL);
		if (0 == bool_status)
		{
			printf("\n!!!COM port read failed");
			printf("Error is %d", GetLastError());
			break;
		}

		// Unpack data and return
		*p_rx_data_len = (uint16_t)((byte_of_data[0] << 8) | (byte_of_data[1]));
		if (*p_rx_data_len == 2 && !strncmp((const char*)failure_status,(const char*)&byte_of_data[2], 2))
		{
			//printf ("\n!!!Receive error");
			//printf ("\n!!!receive length = %d", *p_rx_data_len);
			//printf ("\n!!!failrue status = %04X", failure_status);
			api_status = OPTIGA_COMMS_ERROR;
		}
		else
		{
			memcpy(p_rx_data, byte_of_data + 2, * p_rx_data_len);
			//printf("\nreceive length = %d\n", *p_rx_data_len);
			//for (int i = 0; i < *p_rx_data_len; i++)
			//	printf("%02X:", p_rx_data[i]);
			//printf("\n");
			api_status = OPTIGA_COMMS_SUCCESS;
		}
	} while (0);
	
	return api_status;
}

/**
*  \brief This API closes the communication.
*
* \param[in,out] p_ctx             Pointer to #optiga_comms_t
*
* \retval  #OPTIGA_COMMS_SUCCESS
* \retval  #OPTIGA_COMMS_ERROR
*/
optiga_lib_status_t optiga_comms_close(optiga_comms_t *p_ctx)
{
	optiga_lib_status_t return_status = OPTIGA_COMMS_ERROR;
	com_context_t * p_comm_context = (com_context_t * )(p_ctx->p_comms_ctx);

	do
	{
		if (NULL == p_ctx)
		{
			printf ("\n!!!optiga_comms_close invoked with NULL Pointer");
			break; 
		}
		if (p_comm_context->com_handle)
		{
			printf ("\nClose the %s port done", p_comm_context->com_port);
			CloseHandle(p_comm_context->com_handle);
			p_comm_context->com_handle = 0x00;
		}
		else
		{
			printf ("\n!!! COM Port handle invalid");
		}
	
		if(p_comm_context->com_port)
		{
			free((void *)p_comm_context->com_port);
			p_comm_context->com_port = NULL;
		}
		return_status = OPTIGA_COMMS_SUCCESS;
	} while(0);
	return return_status;
}