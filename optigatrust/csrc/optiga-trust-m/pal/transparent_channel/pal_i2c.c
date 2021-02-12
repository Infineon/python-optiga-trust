/**
* \copyright
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file pal_i2c.c
*
* \brief   This file implements the platform abstraction layer(pal) APIs for I2C.
*
* \ingroup  grPAL
* @{
*/

#include <unistd.h>

#include "optiga/pal/pal_i2c.h"

#if IFX_I2C_LOG_HAL == 1
#define LOG_HAL IFX_I2C_LOG
#else
#include<stdio.h>
#define LOG_HAL(...) //printf(__VA_ARGS__)
#endif

/// I2C device
char * i2c_if = "/dev/i2c-1";

// Slave address not initialization
#define IFXI2C_SLAVE_ADDRESS_INIT 0xFFFF
#define PAL_I2C_MASTER_MAX_BITRATE 100
#define WAIT_500_MS	(500)
/// @cond hidden

void i2c_master_end_of_transmit_callback(void);
void i2c_master_end_of_receive_callback(void);
void invoke_upper_layer_callback (const pal_i2c_t* p_pal_i2c_ctx, optiga_lib_status_t event);

/* Pointer to the current pal i2c context*/
static pal_i2c_t * gp_pal_i2c_current_ctx;

/// @endcond

void invoke_upper_layer_callback (const pal_i2c_t * p_pal_i2c_ctx, optiga_lib_status_t event)
{
    upper_layer_callback_t  upper_layer_handler;
    //lint --e{611} suppress "void* function pointer is type casted to upper_layer_callback_t  type"
    upper_layer_handler = (upper_layer_callback_t )p_pal_i2c_ctx->upper_layer_event_handler;

    upper_layer_handler(p_pal_i2c_ctx->p_upper_layer_ctx , event);
}

/// @cond hidden
// I2C driver callback function when the transmit is completed successfully
void i2c_master_end_of_transmit_callback(void)
{
    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
}


// I2C driver callback function when the receive is completed successfully
void i2c_master_end_of_receive_callback(void)
{
	invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_SUCCESS);
}

// I2C error callback function
void i2c_master_error_detected_callback(void)
{
    //I2C_MASTER_t *p_i2c_master;
    //
    //p_i2c_master = gp_pal_i2c_current_ctx->p_i2c_hw_config;
    //if (I2C_MASTER_IsTxBusy(p_i2c_master))
    //{
    //    //lint --e{534} suppress "Return value is not required to be checked"
    //    I2C_MASTER_AbortTransmit(p_i2c_master);
    //    while (I2C_MASTER_IsTxBusy(p_i2c_master)){}
    //}  

    //if (I2C_MASTER_IsRxBusy(p_i2c_master)) 
    //{
    //    //lint --e{534} suppress "Return value is not required to be checked"
    //    I2C_MASTER_AbortReceive(p_i2c_master);
    //    while (I2C_MASTER_IsRxBusy(p_i2c_master)){}
    //}

    invoke_upper_layer_callback(gp_pal_i2c_current_ctx, PAL_I2C_EVENT_ERROR);
}


void i2c_master_nack_received_callback(void)
{
    i2c_master_error_detected_callback();
}

void i2c_master_arbitration_lost_callback(void)
{
    i2c_master_error_detected_callback();
}


/// @endcond

pal_status_t pal_i2c_init(const pal_i2c_t* p_i2c_context)
{
	int32_t api_status = PAL_I2C_EVENT_ERROR;	
	com_context_t * p_comms_context = (com_context_t *)(p_i2c_context->p_i2c_hw_config);
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

		api_status = PAL_STATUS_SUCCESS;
		printf("Serial port %s opened\n", com_context.com_port);
	}
	
	return api_status;
}


pal_status_t pal_i2c_deinit(const pal_i2c_t* p_i2c_context)
{
	LOG_HAL("pal_i2c_deinit\n. ");
	
    return PAL_STATUS_SUCCESS;
}


pal_status_t pal_i2c_write(const pal_i2c_t* p_i2c_context,uint8_t* p_data , uint16_t length)
{
    pal_status_t status = PAL_STATUS_FAILURE;
    int32_t i2c_write_status;
	com_context_t * COMM_CTX = (com_context_t *)(p_ctx->p_comms_ctx);
	BOOL bool_status;
	uint32_t number_of_bytes_written = 0;
	uint8_t byte_of_data[MAX_TRANSMIT_FRAME_SIZE] = {0};
	uint32_t NoBytesRead;
	uint32_t index = 0;
	uint8_t ok_status[] = {0xf0,0x0f}; 
	uint8_t max_transmit_frame[MAX_TRANSMIT_FRAME_SIZE];

	LOG_HAL("[IFX-HAL]: I2C TX (%d): ", length);
#if 1
    for (int i = 0; i < length; i++)
    {
        LOG_HAL("%02X ", p_data[i]);
    }
#endif
    LOG_HAL("\n");
	printf ("\ntransceive : send length %d", tx_data_length);
	// Form data frame : [tx_data_length byte 1][tx_data_length byte 2][copied p_tx_data which is less than MAX_TRANSMIT_FRAME_SIZE]
	max_transmit_frame[0] = (uint8_t)(tx_data_length >> 8);
	max_transmit_frame[1] = (uint8_t)(tx_data_length);
	memcpy(max_transmit_frame + 2, p_tx_data, tx_data_length);
	
	//Write Data
	printf("\n!!!Writing");
	bool_status = WriteFile(COMM_CTX->com_handle, max_transmit_frame, MAX_TRANSMIT_FRAME_SIZE, (LPDWORD)&number_of_bytes_written, NULL);
	if (0 == bool_status)
	{
		printf ("\n!!!COM port write failed");
		printf("Error is %d", GetLastError());
		break;
	}
	printf("\n!!!Reading");
	bool_status = ReadFile(COMM_CTX->com_handle, &byte_of_data, MAX_TRANSMIT_FRAME_SIZE, (LPDWORD)&NoBytesRead, NULL);
	if (0 == bool_status)
	{
		printf("\n!!!COM port read failed");
		printf("Error is %d", GetLastError());
		((upper_layer_callback_t )(p_i2c_context->upper_layer_event_handler))
										   (p_i2c_context->p_upper_layer_ctx  , PAL_I2C_EVENT_ERROR);

		break;
	}

	// Unpack data and return
	*p_rx_data_len = (uint16_t)((byte_of_data[0] << 8) | (byte_of_data[1]));
	if (*p_rx_data_len == 2 && !strncmp((const char*)ok_status,(const char*)&byte_of_data[2], 2))
	{
		invoke_upper_layer_callback(p_i2c_context, PAL_I2C_EVENT_SUCCESS);
		status = PAL_STATUS_SUCCESS;
	}
	else
	{
		printf ("\n!!!Receive error");
		printf ("\n!!!receive length = %d", *p_rx_data_len);
		printf ("\n!!!failrue status = %04X", failure_status);
		invoke_upper_layer_callback(p_i2c_context, PAL_I2C_EVENT_ERROR);
	}

    return status;
}


pal_status_t pal_i2c_read(const pal_i2c_t* p_i2c_context , uint8_t* p_data , uint16_t length)
{
    int32_t i2c_read_status = PAL_STATUS_FAILURE;
	pal_linux_t *pal_linux;
    

	pal_linux = (pal_linux_t*) p_i2c_context->p_i2c_hw_config;
    //Acquire the I2C bus before read/write
    if (PAL_STATUS_SUCCESS == pal_i2c_acquire(p_i2c_context))
    {    
        gp_pal_i2c_current_ctx = p_i2c_context;
		i2c_read_status = read(pal_linux->i2c_handle,p_data, length);
		if (0 > i2c_read_status)
		{
    		LOG_HAL("[IFX-HAL]: libusb_interrupt_transfer ERROR %d\n.", i2c_read_status);
            //lint --e{611} suppress "void* function pointer is type casted to upper_layer_callback_t  type"
            ((upper_layer_callback_t )(p_i2c_context->upper_layer_event_handler))
                                                       (p_i2c_context->p_upper_layer_ctx  , PAL_I2C_EVENT_ERROR);
													   			//Release I2C Bus
			pal_i2c_release((void *)p_i2c_context);
    		return i2c_read_status;
		}
		else
        {
			LOG_HAL("[IFX-HAL]: I2C RX (%d)\n", length);
#if 1
			for (int i = 0; i < length; i++)
			{
				LOG_HAL("%02X ", p_data[i]);
			}
#endif
			
			i2c_master_end_of_receive_callback();
			i2c_read_status = PAL_STATUS_SUCCESS;
			//reception_started = true;
        }
    }
    else
    {
        i2c_read_status = PAL_STATUS_I2C_BUSY;
        //lint --e{611} suppress "void* function pointer is type casted to upper_layer_callback_t  type"
        ((upper_layer_callback_t )(p_i2c_context->upper_layer_event_handler))
                                                        (p_i2c_context->p_upper_layer_ctx  , PAL_I2C_EVENT_BUSY);
    }
    return i2c_read_status;
}

   

pal_status_t pal_i2c_set_bitrate(const pal_i2c_t* p_i2c_context , uint16_t bitrate)
{
    pal_status_t return_status = PAL_STATUS_FAILURE;
    optiga_lib_status_t event = PAL_I2C_EVENT_ERROR;
	LOG_HAL("pal_i2c_set_bitrate\n. ");
    //Acquire the I2C bus before setting the bitrate
    if (PAL_STATUS_SUCCESS == pal_i2c_acquire(p_i2c_context))
    {    
        // If the user provided bitrate is greater than the I2C master hardware maximum supported value,
        // set the I2C master to its maximum supported value.
        if (bitrate > PAL_I2C_MASTER_MAX_BITRATE)         
        {
            bitrate = PAL_I2C_MASTER_MAX_BITRATE;
        }
        return_status = PAL_STATUS_SUCCESS;
        event = PAL_I2C_EVENT_SUCCESS;
    }
    else
    {
        return_status = PAL_STATUS_I2C_BUSY;
        event = PAL_I2C_EVENT_BUSY;
    }
    if (0 != p_i2c_context->upper_layer_event_handler)
    {
        //lint --e{611} suppress "void* function pointer is type casted to upper_layer_callback_t  type"
        ((upper_layer_callback_t)(p_i2c_context->upper_layer_event_handler))(p_i2c_context->p_upper_layer_ctx  , event);
    }
    //Release I2C Bus
    pal_i2c_release((void *)p_i2c_context);
    return return_status;
}

/**
* @}
*/
