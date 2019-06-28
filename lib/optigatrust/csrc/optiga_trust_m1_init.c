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
#include "optiga/optiga_crypt.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

#include "optiga_trust_m1_init.h"


static volatile optiga_lib_status_t optiga_lib_status;

static void optiga_util_callback(void * context, optiga_lib_status_t return_status)
{
	optiga_lib_status = return_status;
}

//lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_crypt_callback(void * context, optiga_lib_status_t return_status)
{
	optiga_lib_status = return_status;
	if (NULL != context)
	{
		// callback to upper layer here
	}
}

int32_t optiga_init(void* p_crypt, void* p_util)
{
	optiga_lib_status_t return_status;
	optiga_crypt_t * p_local_crypt = p_crypt = NULL;
	optiga_util_t * p_local_util = p_util = NULL;

	do
	{
		/**
         * 1. Create OPTIGA Crypt Instance
         */
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt)
        {
            break;
        }
		
		/**
         * 1. Create OPTIGA Util Instance
         */
		p_local_util = optiga_util_create(0, optiga_util_callback, NULL);
		if (NULL == p_local_util)
        {
            break;
        }
		
		/**
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */        
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(p_local_util, 0);

        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }
        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_open_application is completed
        }
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util open application failed
            break;
        }

		return_status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return return_status;
}

int32_t optiga_deinit(void* p_crypt, void* p_util)
{
	optiga_lib_status_t return_status;
	optiga_crypt_t * p_local_crypt = p_crypt;
	optiga_util_t * p_local_util = p_util;
	
	do
	{
		/**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(p_local_util, 0);
        
        if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }

        // destroy util and crypt instances
        optiga_util_destroy(p_local_util);
		optiga_crypt_destroy(p_local_crypt);
		
		return_status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return return_status;
}

/* optiga_lib_status_t optigam_util_read_data(uint16_t optiga_oid, uint16_t offset, uint8_t * buffer, uint16_t * length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optiga_util_read_data(p_util, optiga_oid, offset, buffer, length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_read_metadata(uint16_t optiga_oid, uint8_t * buffer, uint16_t * length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_read_metadata(p_util, optiga_oid, buffer, length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_write_data(uint16_t optiga_oid, uint8_t write_type, uint16_t offset, const uint8_t * buffer, uint16_t length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_write_data(p_util, optiga_oid, write_type, offset, buffer, length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_write_metadata(uint16_t optiga_oid, const uint8_t * buffer, uint8_t length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_write_metadata(p_util, optiga_oid, buffer, length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_protected_update_start(uint8_t manifest_version, const uint8_t * manifest, uint16_t manifest_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_protected_update_start(p_util, manifest_version, manifest, manifest_length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_protected_update_continue(const uint8_t * manifest_length, uint16_t fragment_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_protected_update_continue(p_util, manifest_length, fragment_length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_protected_update_final(const uint8_t * fragment, uint16_t fragment_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_protected_update_final(p_util, fragment, fragment_length);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

optiga_lib_status_t optigam_util_update_count(uint16_t optiga_counter_oid, uint8_t count)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_LIB_ERROR;

	do
	{
		return_status = optigam_util_update_count(p_util, optiga_counter_oid, count);
		if (OPTIGA_LIB_SUCCESS != return_status)
        {
            break;
        }

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            //Wait until the optiga_util_close_application is completed
        }
        
        if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
        {
            //optiga util close application failed
            break;
        }
	}while(0);
	
	return return_status;
}

void OPTIGAM_UTIL_SET_COMMS_PROTECTION_LEVEL(uint8_t protection_level)
{
	optiga_util_set_comms_params(p_util, OPTIGA_COMMS_PROTECTION_LEVEL, protection_level);
}

void OPTIGAM_UTIL_SET_COMMS_PROTOCOL_VERSION(uint8_t version)
{
	optiga_util_set_comms_params(p_util, OPTIGA_COMMS_PROTOCOL_VERSION, version);
}


LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_random(optiga_rng_type_t rng_type, uint8_t * random_data, uint16_t random_data_length)
{
	CHECK_CRYPT_RESULT(optiga_crypt_random(p_crypt, rng_type, random_data, random_data_length));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_hash_start(optiga_hash_context_t * hash_ctx)
{
	CHECK_CRYPT_RESULT(optiga_crypt_hash_start(p_crypt, hash_ctx));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_hash_update(optiga_hash_context_t * hash_ctx, uint8_t source_of_data_to_hash, const void * data_to_hash)
{
	CHECK_CRYPT_RESULT(optiga_crypt_hash_update(p_crypt, hash_ctx, source_of_data_to_hash, data_to_hash));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_hash_finalize(optiga_hash_context_t * hash_ctx, uint8_t * hash_output)
{
	CHECK_CRYPT_RESULT(optiga_crypt_hash_finalize(p_crypt, hash_ctx, hash_output));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_ecc_generate_keypair(optiga_ecc_curve_t curve_id, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length)
{
	CHECK_CRYPT_RESULT(optiga_crypt_ecc_generate_keypair(p_crypt, curve_id, key_usage, export_private_key, private_key, public_key, public_key_length));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_ecdsa_sign(const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length)
{
	CHECK_CRYPT_RESULT(optiga_crypt_ecdsa_sign(p_crypt, digest, digest_length, private_key, signature, signature_length));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_ecdsa_verify(const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key)
{
	CHECK_CRYPT_RESULT(optiga_crypt_ecdsa_verify(p_crypt, digest, digest_length, signature, signature_length, public_key_source_type, public_key));
}

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_ecdh(optiga_key_id_t private_key, public_key_from_host_t * public_key, bool_t export_to_host, uint8_t * shared_secret);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_tls_prf_sha256(uint16_t secret, const uint8_t * label, uint16_t label_length, const uint8_t * seed, uint16_t seed_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_generate_keypair(optiga_rsa_key_type_t key_type, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_sign(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length, uint16_t salt_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_verify(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key, uint16_t salt_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_generate_pre_master_secret(const uint8_t * optional_data, uint16_t optional_data_length, uint16_t pre_master_secret_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_encrypt_message(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * message, uint16_t message_length, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_encrypt_session(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_decrypt_and_export(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key, uint8_t * message, uint16_t * message_length);

LIBRARY_EXPORTS optigam_lib_status_t optiga_crypt_rsa_decrypt_and_store(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key);

LIBRARY_EXPORTS void OPTIGAM_CRYPT_SET_COMMS_PROTECTION_LEVEL(protection_level);

LIBRARY_EXPORTS void OPTIGAM_CRYPT_SET_COMMS_PROTOCOL_VERSION(version); */
