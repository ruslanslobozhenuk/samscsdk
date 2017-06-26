/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file crypto_tiny.h
 * @brief Tiny crypto.
 */

#ifndef crypto_tiny_h
#define crypto_tiny_h

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <virgil/converters/converters_tiny.h>

#if defined(CRYPTO_ATMEL)
#include <virgil/atecc508a/shared.h>
#endif

typedef enum {
    kDigestData,
    kDigestHash
} digest_t;

#define CRYPTO_SESSION_KEY_SZ	32

/***************************************************************************//**
 * @brief Initialize crypto.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_init();

/***************************************************************************//**
 * @brief Check is crypto ready.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_is_ready();

/***************************************************************************//**
 * @brief Get own device id.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_own_id(uint8_t ** own_id, size_t * own_id_sz);

/***************************************************************************//**
 * @brief Get own public key.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_own_public_key(uint8_t * key[64]);

/***************************************************************************//**
* @brief SHA-256
*
* @param[in] 	data    	Data for hash creation
* @param[in] 	data_sz		Size of data
* @param[out] 	hash        Hash value
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_tiny_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]);

/***************************************************************************//**
* @brief Start SHA-256
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_tiny_hash_start();

/***************************************************************************//**
* @brief Add data to SHA-256 creation
*
* @param[in] 	data    	Data for hash creation
* @param[in] 	data_sz		Size of data
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_tiny_hash_update(const uint8_t * data, size_t data_sz);

/***************************************************************************//**
* @brief Finish SHA-256
*
* @param[out] 	hash    Hash value
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_tiny_hash_finish(const uint8_t * data, size_t data_sz, uint8_t hash[32]);

/***************************************************************************//**
 * @brief Create signature for data.
 *
 * @result "true" if done successfully.
 * .
 ******************************************************************************/
bool crypto_tiny_sign(
#if !defined(CRYPTO_ATMEL)
		const uint8_t * private_key, size_t private_key_sz,
#endif
		const uint8_t * data, size_t data_sz, uint8_t signature[64]);

/***************************************************************************//**
 * @brief Create signature for prepared hash.
 * @result "true" if done successfully.
 *
******************************************************************************/
bool crypto_tiny_sign_hash(
#if !defined(CRYPTO_ATMEL)
		const uint8_t * private_key, size_t private_key_sz,
#endif
		const uint8_t hash[32], uint8_t signature[64]);

/***************************************************************************//**
 * @brief Verify data signature.
 *
 * @result "true" if signature is correct.
 * .
 ******************************************************************************/
bool crypto_tiny_verify(const uint8_t * data, size_t data_sz,
		const uint8_t signature[64],
		const uint8_t public_key[64]);

/***************************************************************************//**
 * @brief Verify signature using prepared hash value.
 *
 * @result "true" if signature is correct
 *
*******************************************************************************/
bool crypto_tiny_verify_hash(const uint8_t hash[32],
		const uint8_t signature[64],
		const uint8_t public_key[64]);

/***************************************************************************//**
 * @brief Encrypt data.
 *
 * @result "true" if done successfully.
 * .
 ******************************************************************************/
bool crypto_tiny_encrypt(const uint8_t * data, size_t data_sz,
		const uint8_t public_key[64],
		uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz);

/***************************************************************************//**
 * @brief Decrypt data
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_decrypt(
#if !defined(CRYPTO_ATMEL)
		const uint8_t * private_key, size_t private_key_sz,
#endif
		const uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz);

#if defined(CRYPTO_ATMEL)
void atecc508a_i2c_irq();
bool atecc508a_load_data(uint8_t slot_id, uint8_t * data, size_t data_sz);
#endif

/***************************************************************************//**
 * @brief Get session key
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_session_key(uint8_t key[CRYPTO_SESSION_KEY_SZ]);

/***************************************************************************//**
 * @brief Create new session key
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_update_session_key();

/***************************************************************************//**
 * @brief Create new session key
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_tiny_random(uint8_t key[32]);

#endif /* crypto_tiny_h */
