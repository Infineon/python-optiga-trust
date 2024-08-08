/**
 * SPDX-FileCopyrightText: 2018-2024 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
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

#include "optiga_trust_init.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "optiga_crypt.h"
#include "optiga_util.h"
#include "pal.h"
#include "pal_ifx_i2c_config.h"
#include "pal_os_event.h"
#include "pal_os_timer.h"

#define LOG_INIT(...)  // printf(__VA_ARGS__)

static volatile optiga_lib_status_t optiga_lib_status;
static optiga_crypt_t *p_local_crypt = NULL;
static optiga_util_t *p_local_util = NULL;

static optiga_lib_status_t wait_for_completion(optiga_lib_status_t return_status) {
    LOG_INIT("[WAIT_FOR_COMPLETION] Entering with return_status %04x\n", return_status);
    if (OPTIGA_LIB_SUCCESS != return_status) {
        return return_status;
    }

    uint16_t tries = 0;
    while (optiga_lib_status == OPTIGA_LIB_BUSY) {
        //LOG_INIT("[WAIT_FOR_COMPLETION] pal_os_event_trigger_registered_callback\n");
        pal_os_event_trigger_registered_callback();
        tries++;
    }

    LOG_INIT("[WAIT_FOR_COMPLETION] Returned from OPTIGA_LIB_BUSY after %d tries.\n", tries);

    if (OPTIGA_LIB_SUCCESS != optiga_lib_status) {
        LOG_INIT("Error: 0x%02X \r\n", optiga_lib_status);
    }

    LOG_INIT("[WAIT_FOR_COMPLETION] Exiting with return_status %04x\n", return_status);
    return optiga_lib_status;
}

static optiga_lib_status_t check_result(optiga_lib_status_t return_status) {
    LOG_INIT("[CHECK_RESULT] return_status %04x\n", return_status);

    optiga_lib_status = OPTIGA_LIB_BUSY;
    return_status = wait_for_completion(return_status);

    LOG_INIT("[CHECK_RESULT] return status: %04x\n", return_status);

    return return_status;
}

static void optiga_util_callback(void *context, optiga_lib_status_t return_status) {
    optiga_lib_status = return_status;
}

//lint --e{818} suppress "argument "context" is not used in the sample provided"
static void optiga_crypt_callback(void *context, optiga_lib_status_t return_status) {
    optiga_lib_status = return_status;
    if (NULL != context) {
        // callback to upper layer here
    }
}

int32_t exp_optiga_init(void) {
    optiga_lib_status_t return_status = OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    do {
        pal_gpio_init(&optiga_reset_0);
        pal_gpio_init(&optiga_vdd_0);
        /**
         * 1. Create OPTIGA Crypt Instance
         */
        p_local_crypt = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == p_local_crypt) {
            break;
        }

        /**
         * 1. Create OPTIGA Util Instance
         */
        p_local_util = optiga_util_create(0, optiga_util_callback, NULL);
        if (NULL == p_local_util) {
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

        while (optiga_lib_status == OPTIGA_LIB_BUSY) {
            pal_os_event_trigger_registered_callback();
        }

        if (OPTIGA_LIB_SUCCESS != optiga_lib_status) {
            return_status = optiga_lib_status;
            LOG_INIT("Error: 0x%02X \r\n", optiga_lib_status);
            break;
        }

        return_status = OPTIGA_LIB_SUCCESS;
    } while (0);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

int32_t exp_optiga_deinit(void) {
    optiga_lib_status_t return_status = OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    do {
        /**
         * Close the application on OPTIGA after all the operations are executed
         * using optiga_util_close_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_close_application(p_local_util, 0);
        if (OPTIGA_LIB_SUCCESS != return_status)
            break;

        while (optiga_lib_status == OPTIGA_LIB_BUSY) {
            pal_os_event_trigger_registered_callback();
        }

        // destroy util and crypt instances
        optiga_util_destroy(p_local_util);
        optiga_crypt_destroy(p_local_crypt);
        pal_os_event_destroy(NULL);

        return_status = OPTIGA_LIB_SUCCESS;
    } while (0);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t
exp_optiga_util_read_data(uint16_t optiga_oid, uint16_t offset, uint8_t *buffer, uint16_t *length) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_read_data(p_local_util, optiga_oid, offset, buffer, length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t
exp_optiga_util_read_metadata(uint16_t optiga_oid, uint8_t *buffer, uint16_t *length) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_read_metadata(p_local_util, optiga_oid, buffer, length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_util_write_data(
    uint16_t optiga_oid,
    uint8_t write_type,
    uint16_t offset,
    const uint8_t *buffer,
    uint16_t length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status =
        optiga_util_write_data(p_local_util, optiga_oid, write_type, offset, buffer, length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t
exp_optiga_util_write_metadata(uint16_t optiga_oid, const uint8_t *buffer, uint8_t length) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_write_metadata(p_local_util, optiga_oid, buffer, length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_util_protected_update_start(
    uint8_t manifest_version,
    const uint8_t *manifest,
    uint16_t manifest_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_protected_update_start(
        p_local_util,
        manifest_version,
        manifest,
        manifest_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_util_protected_update_continue(
    const uint8_t *manifest_length,
    uint16_t fragment_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status =
        optiga_util_protected_update_continue(p_local_util, manifest_length, fragment_length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t
exp_optiga_util_protected_update_final(const uint8_t *fragment, uint16_t fragment_length) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_protected_update_final(p_local_util, fragment, fragment_length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_util_update_count(uint16_t optiga_counter_oid, uint8_t count) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_util_update_count(p_local_util, optiga_counter_oid, count);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
void EXP_OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(uint8_t protection_level) {
    optiga_util_set_comms_params(p_local_util, OPTIGA_COMMS_PROTECTION_LEVEL, protection_level);
}

void EXP_OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(uint8_t version) {
    optiga_util_set_comms_params(p_local_util, OPTIGA_COMMS_PROTOCOL_VERSION, version);
}
#endif

#ifdef OPTIGA_CRYPT_RANDOM_ENABLED
optiga_lib_status_t exp_optiga_crypt_random(
    optiga_rng_type_t rng_type,
    uint8_t *random_data,
    uint16_t random_data_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;
    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_random(p_local_crypt, rng_type, random_data, random_data_length);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RANDOM_ENABLED

#ifdef OPTIGA_CRYPT_HASH_ENABLED
optiga_lib_status_t exp_optiga_crypt_hash_start(optiga_hash_context_t *hash_ctx) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_hash_start(p_local_crypt, hash_ctx);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_crypt_hash_update(
    optiga_hash_context_t *hash_ctx,
    uint8_t source_of_data_to_hash,
    const void *data_to_hash
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);
    return_status =
        optiga_crypt_hash_update(p_local_crypt, hash_ctx, source_of_data_to_hash, data_to_hash);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t
exp_optiga_crypt_hash_finalize(optiga_hash_context_t *hash_ctx, uint8_t *hash_output) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_hash_finalize(p_local_crypt, hash_ctx, hash_output);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_HASH_ENABLED

#ifdef OPTIGA_CRYPT_ECC_GENERATE_KEYPAIR_ENABLED
optiga_lib_status_t exp_optiga_crypt_ecc_generate_keypair(
    optiga_ecc_curve_t curve_id,
    uint8_t key_usage,
    bool_t export_private_key,
    void *private_key,
    uint8_t *public_key,
    uint16_t *public_key_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_ecc_generate_keypair(
        p_local_crypt,
        curve_id,
        key_usage,
        export_private_key,
        private_key,
        public_key,
        public_key_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_ECC_GENERATE_KEYPAIR_ENABLED

#ifdef OPTIGA_CRYPT_ECDSA_SIGN_ENABLED
optiga_lib_status_t exp_optiga_crypt_ecdsa_sign(
    const uint8_t *digest,
    uint8_t digest_length,
    optiga_key_id_t private_key,
    uint8_t *signature,
    uint16_t *signature_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_ecdsa_sign(
        p_local_crypt,
        digest,
        digest_length,
        private_key,
        signature,
        signature_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_ECDSA_SIGN_ENABLED

#ifdef OPTIGA_CRYPT_ECDSA_VERIFY_ENABLED
optiga_lib_status_t exp_optiga_crypt_ecdsa_verify(
    const uint8_t *digest,
    uint8_t digest_length,
    const uint8_t *signature,
    uint16_t signature_length,
    uint8_t public_key_source_type,
    const void *public_key
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);
    return_status = optiga_crypt_ecdsa_verify(
        p_local_crypt,
        digest,
        digest_length,
        signature,
        signature_length,
        public_key_source_type,
        public_key
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_ECDSA_VERIFY_ENABLED

#ifdef OPTIGA_CRYPT_ECDH_ENABLED
optiga_lib_status_t exp_optiga_crypt_ecdh(
    optiga_key_id_t private_key,
    public_key_from_host_t *public_key,
    bool_t export_to_host,
    uint8_t *shared_secret
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status =
        optiga_crypt_ecdh(p_local_crypt, private_key, public_key, export_to_host, shared_secret);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_ECDH_ENABLED

#ifdef OPTIGA_CRYPT_TLS_PRF_SHA256_ENABLED
optiga_lib_status_t exp_optiga_crypt_tls_prf(
    optiga_tls_prf_type_t type,
    uint16_t secret,
    const uint8_t *label,
    uint16_t label_length,
    const uint8_t *seed,
    uint16_t seed_length,
    uint16_t derived_key_length,
    bool_t export_to_host,
    uint8_t *derived_key
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);
    return_status = optiga_crypt_tls_prf(
        p_local_crypt,
        type,
        secret,
        label,
        label_length,
        seed,
        seed_length,
        derived_key_length,
        export_to_host,
        derived_key
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_TLS_PRF_SHA256_ENABLED

#ifdef OPTIGA_CRYPT_HKDF_ENABLED
optiga_lib_status_t exp_optiga_crypt_hkdf(
    optiga_hkdf_type_t type,
    uint16_t secret,
    const uint8_t *salt,
    uint16_t salt_length,
    const uint8_t *info,
    uint16_t info_length,
    uint16_t derived_key_length,
    bool_t export_to_host,
    uint8_t *derived_key
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);
    return_status = optiga_crypt_hkdf(
        p_local_crypt,
        type,
        secret,
        salt,
        salt_length,
        info,
        info_length,
        derived_key_length,
        export_to_host,
        derived_key
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_HKDF_ENABLED

#ifdef OPTIGA_CRYPT_RSA_GENERATE_KEYPAIR_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_generate_keypair(
    optiga_rsa_key_type_t key_type,
    uint8_t key_usage,
    bool_t export_private_key,
    void *private_key,
    uint8_t *public_key,
    uint16_t *public_key_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);
    return_status = optiga_crypt_rsa_generate_keypair(
        p_local_crypt,
        key_type,
        key_usage,
        export_private_key,
        private_key,
        public_key,
        public_key_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_GENERATE_KEYPAIR_ENABLED

#ifdef OPTIGA_CRYPT_RSA_SIGN_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_sign(
    optiga_rsa_signature_scheme_t signature_scheme,
    const uint8_t *digest,
    uint8_t digest_length,
    optiga_key_id_t private_key,
    uint8_t *signature,
    uint16_t *signature_length,
    uint16_t salt_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_sign(
        p_local_crypt,
        signature_scheme,
        digest,
        digest_length,
        private_key,
        signature,
        signature_length,
        salt_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_SIGN_ENABLED

#ifdef OPTIGA_CRYPT_RSA_VERIFY_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_verify(
    optiga_rsa_signature_scheme_t signature_scheme,
    const uint8_t *digest,
    uint8_t digest_length,
    const uint8_t *signature,
    uint16_t signature_length,
    uint8_t public_key_source_type,
    const void *public_key,
    uint16_t salt_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_verify(
        p_local_crypt,
        signature_scheme,
        digest,
        digest_length,
        signature,
        signature_length,
        public_key_source_type,
        public_key,
        salt_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_VERIFY_ENABLED

#ifdef OPTIGA_CRYPT_RSA_PRE_MASTER_SECRET_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_generate_pre_master_secret(
    const uint8_t *optional_data,
    uint16_t optional_data_length,
    uint16_t pre_master_secret_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_generate_pre_master_secret(
        p_local_crypt,
        optional_data,
        optional_data_length,
        pre_master_secret_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_PRE_MASTER_SECRET_ENABLED

#ifdef OPTIGA_CRYPT_RSA_ENCRYPT_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_message(
    optiga_rsa_encryption_scheme_t encryption_scheme,
    const uint8_t *message,
    uint16_t message_length,
    const uint8_t *label,
    uint16_t label_length,
    uint8_t public_key_source_type,
    const void *public_key,
    uint8_t *encrypted_message,
    uint16_t *encrypted_message_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_encrypt_message(
        p_local_crypt,
        encryption_scheme,
        message,
        message_length,
        label,
        label_length,
        public_key_source_type,
        public_key,
        encrypted_message,
        encrypted_message_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_crypt_rsa_encrypt_session(
    optiga_rsa_encryption_scheme_t encryption_scheme,
    const uint8_t *label,
    uint16_t label_length,
    uint8_t public_key_source_type,
    const void *public_key,
    uint8_t *encrypted_message,
    uint16_t *encrypted_message_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_encrypt_session(
        p_local_crypt,
        encryption_scheme,
        label,
        label_length,
        public_key_source_type,
        public_key,
        encrypted_message,
        encrypted_message_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_ENCRYPT_ENABLED

#ifdef OPTIGA_CRYPT_RSA_DECRYPT_ENABLED
optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_export(
    optiga_rsa_encryption_scheme_t encryption_scheme,
    const uint8_t *encrypted_message,
    uint16_t encrypted_message_length,
    const uint8_t *label,
    uint16_t label_length,
    optiga_key_id_t private_key,
    uint8_t *message,
    uint16_t *message_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_decrypt_and_export(
        p_local_crypt,
        encryption_scheme,
        encrypted_message,
        encrypted_message_length,
        label,
        label_length,
        private_key,
        message,
        message_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

optiga_lib_status_t exp_optiga_crypt_rsa_decrypt_and_store(
    optiga_rsa_encryption_scheme_t encryption_scheme,
    const uint8_t *encrypted_message,
    uint16_t encrypted_message_length,
    const uint8_t *label,
    uint16_t label_length,
    optiga_key_id_t private_key
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_rsa_decrypt_and_store(
        p_local_crypt,
        encryption_scheme,
        encrypted_message,
        encrypted_message_length,
        label,
        label_length,
        private_key
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_RSA_DECRYPT_ENABLED

#ifdef OPTIGA_CRYPT_SYM_ENCRYPT_ENABLED
optiga_lib_status_t exp_optiga_crypt_symmetric_encrypt(
    optiga_symmetric_encryption_mode_t encryption_mode,
    optiga_key_id_t symmetric_key_oid,
    const uint8_t *plain_data,
    uint32_t plain_data_length,
    const uint8_t *iv,
    uint16_t iv_length,
    const uint8_t *associated_data,
    uint16_t associated_data_length,
    uint8_t *encrypted_data,
    uint32_t *encrypted_data_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_symmetric_encrypt(
        p_local_crypt,
        encryption_mode,
        symmetric_key_oid,
        plain_data,
        plain_data_length,
        iv,
        iv_length,
        associated_data,
        associated_data_length,
        encrypted_data,
        encrypted_data_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_SYM_ENCRYPT_ENABLED

optiga_lib_status_t exp_optiga_crypt_symmetric_decrypt(
    optiga_symmetric_encryption_mode_t encryption_mode,
    optiga_key_id_t symmetric_key_oid,
    const uint8_t *encrypted_data,
    uint32_t encrypted_data_length,
    const uint8_t *iv,
    uint16_t iv_length,
    const uint8_t *associated_data,
    uint16_t associated_data_length,
    uint8_t *plain_data,
    uint32_t *plain_data_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_symmetric_encrypt(
        p_local_crypt,
        encryption_mode,
        symmetric_key_oid,
        encrypted_data,
        encrypted_data_length,
        iv,
        iv_length,
        associated_data,
        associated_data_length,
        plain_data,
        plain_data_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}

#ifdef OPTIGA_CRYPT_HMAC_ENABLED
optiga_lib_status_t exp_optiga_crypt_hmac(
    optiga_hmac_type_t type,
    uint16_t secret,
    const uint8_t *input_data,
    uint32_t input_data_length,
    uint8_t *mac,
    uint32_t *mac_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_hmac(
        p_local_crypt,
        type,
        secret,
        input_data,
        input_data_length,
        mac,
        mac_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_HMAC_ENABLED

#ifdef OPTIGA_CRYPT_SYM_GENERATE_KEY_ENABLED
optiga_lib_status_t exp_optiga_crypt_symmetric_generate_key(
    optiga_symmetric_key_type_t key_type,
    uint8_t key_usage,
    bool_t export_symmetric_key,
    void *symmetric_key
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_symmetric_generate_key(
        p_local_crypt,
        key_type,
        key_usage,
        export_symmetric_key,
        symmetric_key
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_SYM_GENERATE_KEY_ENABLED

#ifdef OPTIGA_CRYPT_GENERATE_AUTH_CODE_ENABLED
optiga_lib_status_t exp_optiga_crypt_generate_auth_code(
    optiga_rng_type_t rng_type,
    const uint8_t *optional_data,
    uint16_t optional_data_length,
    uint8_t *random_data,
    uint16_t random_data_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_generate_auth_code(
        p_local_crypt,
        rng_type,
        optional_data,
        optional_data_length,
        random_data,
        random_data_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_GENERATE_AUTH_CODE_ENABLED

#ifdef OPTIGA_CRYPT_HMAC_VERIFY_ENABLED
optiga_lib_status_t exp_optiga_crypt_hmac_verify(
    optiga_hmac_type_t type,
    uint16_t secret,
    const uint8_t *input_data,
    uint32_t input_data_length,
    const uint8_t *hmac,
    uint32_t hmac_length
) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_hmac_verify(
        p_local_crypt,
        type,
        secret,
        input_data,
        input_data_length,
        hmac,
        hmac_length
    );
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_HMAC_VERIFY_ENABLED

#ifdef OPTIGA_CRYPT_CLEAR_AUTO_STATE_ENABLED
optiga_lib_status_t exp_optiga_crypt_clear_auto_state(uint16_t secret) {
    optiga_lib_status_t return_status = (int32_t)OPTIGA_DEVICE_ERROR;

    LOG_INIT("[init]   %s\n", __FUNCTION__);

    return_status = optiga_crypt_clear_auto_state(p_local_crypt, secret);
    return_status = check_result(return_status);

    LOG_INIT("[init]   %s: return_status: %04x\n", __FUNCTION__, return_status);

    return return_status;
}
#endif  // OPTIGA_CRYPT_CLEAR_AUTO_STATE_ENABLED

#ifdef OPTIGA_COMMS_SHIELDED_CONNECTION
void EXP_OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(protection_level) {
    optiga_crypt_set_comms_params(p_local_crypt, OPTIGA_COMMS_PROTECTION_LEVEL, protection_level);
}

void EXP_OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(version) {
    optiga_crypt_set_comms_params(p_local_crypt, OPTIGA_COMMS_PROTOCOL_VERSION, version);
}
#endif
