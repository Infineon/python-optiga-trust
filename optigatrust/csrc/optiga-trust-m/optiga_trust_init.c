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
#include "optiga/pal/pal_os_timer.h"
#include "optiga/pal/pal_ifx_i2c_config.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

#include "optiga_trust_init.h"


#define WAIT_FOR_COMPLETION(ret) \
	if (OPTIGA_LIB_SUCCESS != ret)\
	{\
		break;\
	}\
	while (optiga_lib_status == OPTIGA_LIB_BUSY) \
	{\
		pal_os_timer_delay_in_milliseconds(1);\
	} \
	\
	if (OPTIGA_LIB_SUCCESS != optiga_lib_status)\
	{ \
			ret = optiga_lib_status;\
			printf("Error: 0x%02X \r\n", optiga_lib_status);\
			break; \
	}

#define CHECK_RESULT(expr) \
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR; \
\
	do\
	{\
		optiga_lib_status = OPTIGA_LIB_BUSY;\
		return_status = expr;\
		WAIT_FOR_COMPLETION(return_status);\
	} while (0);\
\
	return return_status;


static volatile optiga_lib_status_t optiga_lib_status;
static optiga_crypt_t * p_local_crypt = NULL;
static optiga_util_t * p_local_util = NULL;


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

int32_t exp_optiga_init(void)
{
	optiga_lib_status_t return_status = OPTIGA_DEVICE_ERROR;

	do
	{
        pal_gpio_init(&optiga_reset_0);
        pal_gpio_init(&optiga_vdd_0);
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
			break; 
			
		while (optiga_lib_status == OPTIGA_LIB_BUSY) 
		{
			pal_os_timer_delay_in_milliseconds(1); 
		} 
				
		if (OPTIGA_LIB_SUCCESS != optiga_lib_status)
		{ 
			return_status = optiga_lib_status;
			printf("Error: 0x%02X \r\n", optiga_lib_status); 
			break; 
		}

		return_status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return return_status;
}

int32_t exp_optiga_deinit(void)
{
	optiga_lib_status_t return_status = OPTIGA_DEVICE_ERROR;
	
	do
	{
		/**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(p_local_util, 0);
		if (OPTIGA_LIB_SUCCESS != return_status)
		break; 
			
		while (optiga_lib_status == OPTIGA_LIB_BUSY) 
		{
			pal_os_timer_delay_in_milliseconds(1);
		} 
				
        // destroy util and crypt instances
        optiga_util_destroy(p_local_util);
		optiga_crypt_destroy(p_local_crypt);
		pal_os_event_destroy(NULL);
		
		return_status = OPTIGA_LIB_SUCCESS;
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_read_data(uint16_t optiga_oid, uint16_t offset, uint8_t * buffer, uint16_t * length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
	
	do
	{
		CHECK_RESULT(optiga_util_read_data(p_local_util, optiga_oid, offset, buffer, length));
	}while (0); 
						
	return return_status; 
}

optiga_lib_status_t exp_optiga_util_read_metadata(uint16_t optiga_oid, uint8_t * buffer, uint16_t * length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_read_metadata(p_local_util, optiga_oid, buffer, length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_write_data(uint16_t optiga_oid, uint8_t write_type, uint16_t offset, const uint8_t * buffer, uint16_t length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_write_data(p_local_util, optiga_oid, write_type, offset, buffer, length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_write_metadata(uint16_t optiga_oid, const uint8_t * buffer, uint8_t length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_write_metadata(p_local_util, optiga_oid, buffer, length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_protected_update_start(uint8_t manifest_version, const uint8_t * manifest, uint16_t manifest_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_protected_update_start(p_local_util, manifest_version, manifest, manifest_length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_protected_update_continue(const uint8_t * manifest_length, uint16_t fragment_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_protected_update_continue(p_local_util, manifest_length, fragment_length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_protected_update_final(const uint8_t * fragment, uint16_t fragment_length)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		CHECK_RESULT(optiga_util_protected_update_final(p_local_util, fragment, fragment_length));
	} while (0);

	return return_status;
}

optiga_lib_status_t exp_optiga_util_update_count(uint16_t optiga_counter_oid, uint8_t count)
{
	optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

	do
	{
		return_status = optiga_util_update_count(p_local_util, optiga_counter_oid, count);
		WAIT_FOR_COMPLETION(return_status);
	}while(0);
	
	return return_status;
}

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
void EXP_OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(uint8_t protection_level)
{
	optiga_util_set_comms_params(p_local_util, OPTIGA_COMMS_PROTECTION_LEVEL, protection_level);
}

void EXP_OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(uint8_t version)
{
	optiga_util_set_comms_params(p_local_util, OPTIGA_COMMS_PROTOCOL_VERSION, version);
}
#endif

optiga_lib_status_t exp_optiga_crypt_random(optiga_rng_type_t rng_type, uint8_t * random_data, uint16_t random_data_length)
{
	CHECK_RESULT(optiga_crypt_random(p_local_crypt, rng_type, random_data, random_data_length));
}

optiga_lib_status_t exp_optiga_crypt_hash_start(optiga_hash_context_t * hash_ctx)
{
	CHECK_RESULT(optiga_crypt_hash_start(p_local_crypt, hash_ctx));
}

optiga_lib_status_t exp_optiga_crypt_hash_update(optiga_hash_context_t * hash_ctx, uint8_t source_of_data_to_hash, const void * data_to_hash)
{
	CHECK_RESULT(optiga_crypt_hash_update(p_local_crypt, hash_ctx, source_of_data_to_hash, data_to_hash));
}

optiga_lib_status_t exp_optiga_crypt_hash_finalize(optiga_hash_context_t * hash_ctx, uint8_t * hash_output)
{
	CHECK_RESULT(optiga_crypt_hash_finalize(p_local_crypt, hash_ctx, hash_output));
}

optiga_lib_status_t exp_optiga_crypt_ecc_generate_keypair(optiga_ecc_curve_t curve_id, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length)
{
	CHECK_RESULT(optiga_crypt_ecc_generate_keypair(p_local_crypt, curve_id, key_usage, export_private_key, private_key, public_key, public_key_length));
}

optiga_lib_status_t exp_optiga_crypt_ecdsa_sign(const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length)
{
	CHECK_RESULT(optiga_crypt_ecdsa_sign(p_local_crypt, digest, digest_length, private_key, signature, signature_length));
}

optiga_lib_status_t exp_optiga_crypt_ecdsa_verify(const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key)
{
	CHECK_RESULT(optiga_crypt_ecdsa_verify(p_local_crypt, digest, digest_length, signature, signature_length, public_key_source_type, public_key));
}

optiga_lib_status_t exp_optiga_crypt_ecdh(optiga_key_id_t private_key, public_key_from_host_t * public_key, bool_t export_to_host, uint8_t * shared_secret)
{
	CHECK_RESULT(optiga_crypt_ecdh(p_local_crypt, private_key, public_key, export_to_host, shared_secret));
}

optiga_lib_status_t exp_optiga_crypt_tls_prf_sha256(uint16_t secret, const uint8_t * label, uint16_t label_length, const uint8_t * seed, uint16_t seed_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_tls_prf(p_local_crypt, OPTIGA_TLS12_PRF_SHA_256, secret, label, label_length, seed, seed_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_tls_prf_sha384(uint16_t secret, const uint8_t * label, uint16_t label_length, const uint8_t * seed, uint16_t seed_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_tls_prf(p_local_crypt, OPTIGA_TLS12_PRF_SHA_384, secret, label, label_length, seed, seed_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_tls_prf_sha512(uint16_t secret, const uint8_t * label, uint16_t label_length, const uint8_t * seed, uint16_t seed_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_tls_prf(p_local_crypt, OPTIGA_TLS12_PRF_SHA_512, secret, label, label_length, seed, seed_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_hkdf_sha256(uint16_t secret, const uint8_t * salt, uint16_t salt_length, const uint8_t * info, uint16_t info_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_hkdf(p_local_crypt, OPTIGA_HKDF_SHA_256, secret, salt, salt_length, info, info_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_hkdf_sha384(uint16_t secret, const uint8_t * salt, uint16_t salt_length, const uint8_t * info, uint16_t info_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_hkdf(p_local_crypt, OPTIGA_HKDF_SHA_384, secret, salt, salt_length, info, info_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_hkdf_sha512(uint16_t secret, const uint8_t * salt, uint16_t salt_length, const uint8_t * info, uint16_t info_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key)
{
	CHECK_RESULT(optiga_crypt_hkdf(p_local_crypt, OPTIGA_HKDF_SHA_512, secret, salt, salt_length, info, info_length, derived_key_length, export_to_host, derived_key));
}

optiga_lib_status_t exp_optiga_crypt_rsa_generate_keypair(optiga_rsa_key_type_t key_type, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length)
{
	CHECK_RESULT(optiga_crypt_rsa_generate_keypair(p_local_crypt, key_type, key_usage, export_private_key, private_key, public_key, public_key_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_sign(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length, uint16_t salt_length)
{
	CHECK_RESULT(optiga_crypt_rsa_sign(p_local_crypt, signature_scheme, digest, digest_length, private_key, signature, signature_length, salt_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_verify(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key, uint16_t salt_length)
{
	CHECK_RESULT(optiga_crypt_rsa_verify(p_local_crypt, signature_scheme, digest, digest_length, signature, signature_length, public_key_source_type, public_key, salt_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_generate_pre_master_secret(const uint8_t * optional_data, uint16_t optional_data_length, uint16_t pre_master_secret_length)
{
	CHECK_RESULT(optiga_crypt_rsa_generate_pre_master_secret(p_local_crypt, optional_data, optional_data_length, pre_master_secret_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_message(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * message, uint16_t message_length, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length)
{
	CHECK_RESULT(optiga_crypt_rsa_encrypt_message(p_local_crypt, encryption_scheme, message, message_length, label, label_length, public_key_source_type, public_key, encrypted_message, encrypted_message_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_session(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length)
{
	CHECK_RESULT(optiga_crypt_rsa_encrypt_session(p_local_crypt, encryption_scheme, label, label_length, public_key_source_type, public_key, encrypted_message, encrypted_message_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_export(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key, uint8_t * message, uint16_t * message_length)
{
	CHECK_RESULT(optiga_crypt_rsa_decrypt_and_export(p_local_crypt, encryption_scheme, encrypted_message, encrypted_message_length, label, label_length, private_key, message, message_length));
}

optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_store(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key)
{
	CHECK_RESULT(optiga_crypt_rsa_decrypt_and_store(p_local_crypt, encryption_scheme, encrypted_message, encrypted_message_length, label, label_length, private_key));
}

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
void EXP_OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(protection_level)
{
	optiga_crypt_set_comms_params(p_local_crypt, OPTIGA_COMMS_PROTECTION_LEVEL, protection_level);
}

void EXP_OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(version)
{
	optiga_crypt_set_comms_params(p_local_crypt, OPTIGA_COMMS_PROTOCOL_VERSION, version);
}
#endif
