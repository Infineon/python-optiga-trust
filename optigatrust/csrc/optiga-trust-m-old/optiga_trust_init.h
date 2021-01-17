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

LIBRARY_EXPORTS int32_t exp_optiga_init(void);

LIBRARY_EXPORTS int32_t exp_optiga_deinit(void);


LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_read_data(uint16_t optiga_oid, uint16_t offset, uint8_t * buffer, uint16_t * length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_read_metadata(uint16_t optiga_oid, uint8_t * buffer, uint16_t * length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_write_data(uint16_t optiga_oid, uint8_t write_type, uint16_t offset, const uint8_t * buffer, uint16_t length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_write_metadata(uint16_t optiga_oid, const uint8_t * buffer, uint8_t length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_protected_update_start(uint8_t manifest_version, const uint8_t * manifest, uint16_t manifest_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_protected_update_continue(const uint8_t * fragment, uint16_t fragment_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_protected_update_final(const uint8_t * fragment, uint16_t fragment_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_util_update_count(uint16_t optiga_counter_oid, uint8_t count);

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
LIBRARY_EXPORTS void EXP_OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(uint8_t protection_level);

LIBRARY_EXPORTS void EXP_OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(uint8_t version);
#endif

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_random(optiga_rng_type_t rng_type, uint8_t * random_data, uint16_t random_data_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_hash_start(optiga_hash_context_t * hash_ctx);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_hash_update(optiga_hash_context_t * hash_ctx, uint8_t source_of_data_to_hash, const void * data_to_hash);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_hash_finalize(optiga_hash_context_t * hash_ctx, uint8_t * hash_output);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_ecc_generate_keypair(optiga_ecc_curve_t curve_id, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_ecdsa_sign(const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_ecdsa_verify(const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_ecdh(optiga_key_id_t private_key, public_key_from_host_t * public_key, bool_t export_to_host, uint8_t * shared_secret);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_tls_prf_sha256(uint16_t secret, const uint8_t * label, uint16_t label_length, const uint8_t * seed, uint16_t seed_length, uint16_t derived_key_length, bool_t export_to_host, uint8_t * derived_key);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_generate_keypair(optiga_rsa_key_type_t key_type, uint8_t key_usage, bool_t export_private_key, void * private_key, uint8_t * public_key, uint16_t * public_key_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_sign(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, optiga_key_id_t private_key, uint8_t * signature, uint16_t * signature_length, uint16_t salt_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_verify(optiga_rsa_signature_scheme_t signature_scheme, const uint8_t * digest, uint8_t digest_length, const uint8_t * signature, uint16_t signature_length, uint8_t public_key_source_type, const void * public_key, uint16_t salt_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_generate_pre_master_secret(const uint8_t * optional_data, uint16_t optional_data_length, uint16_t pre_master_secret_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_message(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * message, uint16_t message_length, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_session(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * label, uint16_t label_length, uint8_t public_key_source_type, const void * public_key, uint8_t * encrypted_message, uint16_t * encrypted_message_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_export(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key, uint8_t * message, uint16_t * message_length);

LIBRARY_EXPORTS optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_store(optiga_rsa_encryption_scheme_t encryption_scheme, const uint8_t * encrypted_message, uint16_t encrypted_message_length, const uint8_t * label, uint16_t label_length, optiga_key_id_t private_key);

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
LIBRARY_EXPORTS void EXP_OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(protection_level);

LIBRARY_EXPORTS void EXP_OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(version);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _OPTIGA_TRUST_INIT_H_ */