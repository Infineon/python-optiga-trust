/**
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
*
* \file optiga_trust_init.h
*
* \brief   This file defines the functions to initialise.
*
* \ingroup  grIFXI2C
* @{
*/
#ifndef _OPTIGA_TRUST_INIT_H_
#define _OPTIGA_TRUST_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************************************************************
* HEADER FILES
**********************************************************************************************************************/
// Protocol Stack Includes
#include <stdint.h>
#include "optiga/common/Datatypes.h"

LIBRARY_EXPORTS int32_t optiga_init(void);

LIBRARY_EXPORTS int32_t optiga_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* _OPTIGA_TRUST_INIT_H_ */