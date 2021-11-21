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

pal_status_t pal_i2c_init(const pal_i2c_t* p_i2c_context)
{
    return PAL_STATUS_SUCCESS;
}


pal_status_t pal_i2c_deinit(const pal_i2c_t* p_i2c_context)
{
    return PAL_STATUS_SUCCESS;
}


pal_status_t pal_i2c_write(const pal_i2c_t* p_i2c_context,uint8_t* p_data , uint16_t length)
{
    return PAL_STATUS_SUCCESS;
}


pal_status_t pal_i2c_read(const pal_i2c_t* p_i2c_context , uint8_t* p_data , uint16_t length)
{
    return PAL_STATUS_SUCCESS;
}

   

pal_status_t pal_i2c_set_bitrate(const pal_i2c_t* p_i2c_context , uint16_t bitrate)
{
    return PAL_STATUS_SUCCESS;
}

/**
* @}
*/
