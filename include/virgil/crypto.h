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

/***************************************************************************//**
 * @file crypto_wrapper.h
 * @brief Wrapper for cryptographic functionality.
 *
 * Key pair creation, encryption/decryption and signing plus sign checking.
 *
 ******************************************************************************/

#ifndef CRYPTOWRAPPER_H
#define CRYPTOWRAPPER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VIRGIL_PRIVATE_KEY_MAX_SIZE 150
#define VIRGIL_PUBLIC_KEY_MAX_SIZE 100
#define VIRGIL_SIGNATURE_MAX_SIZE 128

/***************************************************************************//**
 * @brief Initialize crypto.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_init();

/***************************************************************************//**
 * @brief Check is crypto ready.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_is_ready();

/***************************************************************************//**
 * @brief Get own device id.
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_own_id(uint8_t ** own_id, size_t * own_id_sz);

/***************************************************************************//**
 * @brief Create key pair and save to keys container.
 *
 * @param[out] private_key          private key
 * @param[in]  private_key_buf_sz   private key buffer's size
 * @param[out] private_key_sz       result size of private key
 *
 * @param[out] public_key           public key
 * @param[in]  public_key_buf_sz    private key buffer's size
 * @param[out] public_key_sz        result size of public key
 *
 * @result "true" if keys creation successfully.
 *
 ******************************************************************************/
bool crypto_create_key_pair(uint8_t * private_key, size_t private_key_buf_sz, size_t * private_key_sz,
		uint8_t * public_key, size_t public_key_buf_sz, size_t * public_key_sz);

/***************************************************************************//**
 * @brief Encrypt data.
 *
 * @param[in]       recipient_id  	id of recipient.
 * @param[in]       recipient_id_sz size of id
 * @param[in]       public_key    	Public key of recipient.
 * @param[in]       public_key_sz 	Size of public key of recipient
 * @param[in]  		data            Data array
 * @param[in]       data_sz         Size of data
 * @param[in]       buf_sz          Size of data buffer
 * @param[out]      out_data_sz     Size of encrypted data
 *
 * @result "true" if done successfully.
 * .
 ******************************************************************************/
bool crypto_encrypt(const uint8_t * recipient_id, size_t recipient_id_sz,
                           const uint8_t * public_key, size_t public_key_sz,
                           uint8_t * data, size_t data_sz,
						   uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz);

/***************************************************************************//**
 * @brief Decrypt data
 *
 * @param[in]           recipient_id		recipient's Id
 * @param[in]           recipient_id_sz     size of id
 * @param[in]           private_key         recipient private key.
 * @param[in]           private_key_sz      Size of private key
 * @param[in]       	data                Data array
 * @param[in]           data_sz             Size of data
 * @param[in]           buf_sz              Size of data buffer
 * @param[out]          out_data_sz         Size of encrypted data
 * .
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_decrypt(const uint8_t * recipient_id, size_t recipient_id_sz, const uint8_t * private_key, size_t private_key_sz,
		uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz);

/***************************************************************************//**
 * @brief Create signature for data.
 *
 * @param[in]   private_key     Own private key.
 * @param[in]   private_key_sz  Size of own private key
 * @param[in]   data            Data
 * @param[in]   data_sz         Size of data
 * @param[out]  sign_data       Signature data
 * @param[in]   buf_sz          Size of signature data buffer
 * @param[out]  sign_data_sz    Size of signature data
 *
 * @result "true" if done successfully.
 * .
 ******************************************************************************/
bool crypto_sign(const uint8_t * private_key, size_t private_key_sz, const uint8_t * data, size_t data_sz, uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz);

/***************************************************************************//**
 * @brief Create signature for prepared hash.
 *
 * @param[in]   private_key     Own private key.
 * @param[in]   private_key_sz  Size of own private key
 * @param[in]   hash            Hash
 * @param[out]  sign_data       Signature data
 * @param[in]   buf_sz          Size of signature data buffer
 * @param[out]  sign_data_sz    Size of signature data
 *
 * @result "true" if done successfully.
 *
 ******************************************************************************/
bool crypto_sign_hash(const uint8_t * private_key, size_t private_key_sz, const uint8_t hash[32], uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz);

/***************************************************************************//**
 * @brief Verify data signature.
 *
 * @param[in] public_key    Sender's public key
 * @param[in] public_key_sz Size of public key
 * @param[in] sign          Signature data
 * @param[in] sign_sz       Signature data size
 * @param[in] data          Data
 * @param[in] data_sz       Size of data
 *
 * @result "true" if signature is correct.
 * .
 ******************************************************************************/
bool crypto_verify(const uint8_t * public_key, size_t public_key_sz, const uint8_t * sign, size_t sign_sz, const uint8_t * data, size_t data_sz);

/***************************************************************************//**
* @brief Verify signature using prepared hash value.
*
* @param[in] public_key    Sender's public key
* @param[in] public_key_sz Size of public key
* @param[in] sign          Signature data
* @param[in] sign_sz       Signature data size
* @param[in] hash          Hash
*
* @result "true" if signature is correct
*
*******************************************************************************/
bool crypto_verify_hash(const uint8_t * public_key, size_t public_key_sz, const uint8_t * sign, size_t sign_sz, const uint8_t hash[32]);

/***************************************************************************//**
* @brief AES128-CBC encryption.
*
* @param[in] input    	Data to be encrypted
* @param[in] size		Size of data
* @param[in] key        Key for encryption
* @param[in] iv			Initialization vector
* @param[out] output    Encrypted data
*
* @result "true" if encryption has been done correctly
*
*******************************************************************************/
bool crypto_aes_encrypt(uint8_t * input, size_t size, const uint8_t key[16], const uint8_t iv[16], uint8_t * output);

/***************************************************************************//**
* @brief AES128-CBC decryption.
*
* @param[in] input    	Data to be decrypted
* @param[in] size		Size of data
* @param[in] key        Key for decryption
* @param[in] iv			Initialization vector
* @param[out] output    Decrypted data
*
* @result "true" if decryption has been done correctly
*
*******************************************************************************/
bool crypto_aes_decrypt(uint8_t * input, size_t size, const uint8_t key[16], const uint8_t iv[16], uint8_t * output);

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
bool crypto_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]);

/***************************************************************************//**
* @brief Start SHA-256
*
* @param[out] 	ctx    	hash context
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_hash_start(void ** ctx);

/***************************************************************************//**
* @brief Add data to SHA-256 creation
*
* @param[int] 	ctx    		Hash context
* @param[in] 	data    	Data for hash creation
* @param[in] 	data_sz		Size of data
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_hash_update(void * ctx, const uint8_t * data, size_t data_sz);

/***************************************************************************//**
* @brief Finish SHA-256
*
* @param[int] 	ctx    	Hash context
* @param[out] 	hash    Hash value
*
* @result "true" if has been done correctly
*
*******************************************************************************/
bool crypto_hash_finish(void * ctx, const uint8_t * data, size_t data_sz, uint8_t hash[32]);

#endif // CRYPTOWRAPPER_H
