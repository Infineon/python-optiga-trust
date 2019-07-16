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
* \file optiga_trust_init.c
*
* \brief   This sample demonstrates OPTIGA use cases.
*
* \ingroup grOptigaExamples
* @{
*/
/* Standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* OPTIGA(TM) Trust X includes */
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

#include "optiga_trust_init.h"


extern void pal_gpio_init(void);
extern void pal_gpio_deinit(void);
extern pal_status_t pal_init(void);

#ifdef USE_LIBUSB_PAL
extern ifx_i2c_context_t ifx_i2c_context_1;
#define IFX_I2C_CONTEXT ifx_i2c_context_1
#else
extern ifx_i2c_context_t ifx_i2c_context_0;
#define IFX_I2C_CONTEXT ifx_i2c_context_0
#endif

optiga_comms_t optiga_comms = { (void*)&IFX_I2C_CONTEXT, NULL,NULL, OPTIGA_COMMS_SUCCESS };

int32_t optiga_init(void)
{
	int32_t status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		pal_gpio_init();
		pal_os_event_init();
#ifdef USE_LIBUSB_PAL
		if (pal_init() != PAL_STATUS_SUCCESS)
			break;
#endif

		status = optiga_util_open_application(&optiga_comms);
		if (OPTIGA_LIB_SUCCESS != status)
		{
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return status;
}

int32_t optiga_deinit(void)
{
	int32_t status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		pal_gpio_deinit();
		status = optiga_comms_close(&optiga_comms);
		if (OPTIGA_LIB_SUCCESS != status)
		{
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return status;
}