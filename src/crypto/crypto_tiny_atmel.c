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
 * @file crypto_tiny_atmel.h
 */

#if defined(CRYPTO_ATMEL)

#include <atca_cfgs.h>
#include <basic/atca_basic.h>
#include <crypto/hashes/sha2_routines.h>
#include <atcacert/atcacert_def.h>

#include <virgil/crypto_tiny.h>
#include <virgil/converters/converters_tiny.h>
#include <virgil/aes/aes.h>
#include <virgil/atecc508a/data.h>

#if defined (ATECC508A_SHARED)
#define _own_public_key 	(atecc508a_ctx._own_public_key)
#define _device_id 			(atecc508a_ctx._device_id)
#define _device_id_sz 		(atecc508a_ctx._device_id_sz)
#else
static uint8_t _own_public_key[64];
static uint8_t _device_id[32];
static size_t _device_id_sz = 0;
#endif

#if defined(SOFT_SHA256)
static sw_sha256_ctx m_sha256_ctx;
#endif

typedef enum {
    kSignOp,
    kVerifyOp
} sign_verify_t;

/******************************************************************************/
bool crypto_tiny_init() {
#if 0
    memset(_own_public_key, 0, 64);
#endif

#if defined (ATCA_HAL_KIT_HID)
    return ATCA_SUCCESS == atcab_init(&cfg_ecc508_kithid_default);
#elif defined (ATCA_HAL_I2C)
    return ATCA_SUCCESS == atcab_init(&cfg_ateccx08a_i2c_default);
#endif
}

/******************************************************************************/
bool crypto_tiny_is_ready() {
	bool isLocked;
	return ATCA_SUCCESS == atcab_is_locked(LOCK_ZONE_CONFIG, &isLocked) && isLocked;
}

/******************************************************************************/
bool crypto_tiny_own_id(uint8_t ** own_id, size_t * own_id_sz) {
	uint8_t real_id[9];

	if (!_device_id_sz) {
		if (ATCA_SUCCESS != atcab_read_serial_number(real_id)
				|| !crypto_tiny_hash(real_id, sizeof(real_id), _device_id)) {
			return false;
		}
	}

	*own_id = _device_id;
	*own_id_sz = _device_id_sz = ATCA_SHA_DIGEST_SIZE;

	return true;
}

/******************************************************************************/
bool crypto_tiny_own_public_key(uint8_t * key[64]) {
	if (!_own_public_key[0] && !_own_public_key[1]) {
		if (ATCA_SUCCESS != atcab_get_pubkey(PRIVATE_KEY_SLOT, _own_public_key)) {
			return false;
		}
	}

	*key = _own_public_key;

	return true;
}


/******************************************************************************/
bool crypto_tiny_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
#if defined(SOFT_SHA256)
	sw_sha256(data, data_sz, hash);
	return true;
#else
	return ATCA_SUCCESS == atcab_sha(data_sz, data, hash);
#endif
}

/******************************************************************************/
bool crypto_tiny_hash_start() {
#if defined(SOFT_SHA256)
	sw_sha256_init(&m_sha256_ctx);
	return true;
#else
	return ATCA_SUCCESS == atcab_sha_start();
#endif
}

/******************************************************************************/
bool crypto_tiny_hash_update(const uint8_t * data, size_t data_sz) {
#if defined(SOFT_SHA256)
	sw_sha256_update(&m_sha256_ctx, data, data_sz);
	return true;
#else
	return ATCA_SUCCESS == atcab_sha_update(data_sz, data);
#endif
}

/******************************************************************************/
bool crypto_tiny_hash_finish(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
#if defined(SOFT_SHA256)
	if (data && data_sz) {
		sw_sha256_update(&m_sha256_ctx, data, data_sz);
	}
	sw_sha256_final(&m_sha256_ctx, hash);
	return true;
#else
	return ATCA_SUCCESS == atcab_sha_end(hash, data_sz, data);
#endif
}

/******************************************************************************/
static bool _atecc508a_sign_verify_internal(uint8_t slot,
										 const uint8_t * data, size_t data_sz,
										 uint8_t signature[ATCA_SIG_SIZE],
										 const uint8_t public_key[ATCA_PUB_KEY_SIZE],
                                         digest_t digest_type,
										 sign_verify_t operation) {
	uint8_t hash[ATCA_SHA_DIGEST_SIZE];
	bool is_verified = false;

    if (kDigestData == digest_type) {
        if (!crypto_tiny_hash(data, data_sz, hash)) {
            return false;
        }
    } else {
    	memcpy(hash, data, ATCA_SHA_DIGEST_SIZE);
    }

    if (kSignOp == operation) {
    	return  ATCA_SUCCESS == atcab_sign(slot, hash, signature);
    } else {
    	atcab_verify_extern(hash, signature, public_key, &is_verified);
    	return is_verified;
    }
}

/******************************************************************************/
bool crypto_tiny_sign(const uint8_t * data, size_t data_sz, uint8_t signature[64]) {
    return _atecc508a_sign_verify_internal(PRIVATE_KEY_SLOT, data, data_sz, signature, 0, kDigestData, kSignOp);
}

/******************************************************************************/
bool crypto_tiny_sign_hash(const uint8_t hash[32], uint8_t signature[64]) {
    return _atecc508a_sign_verify_internal(PRIVATE_KEY_SLOT, hash, ATCA_SHA_DIGEST_SIZE, signature, 0, kDigestHash, kSignOp);
}

/******************************************************************************/
bool crypto_tiny_verify(const uint8_t * data, size_t data_sz,
		const uint8_t signature[64],
		const uint8_t public_key[64]) {
    return _atecc508a_sign_verify_internal(0, data, data_sz, (uint8_t *)signature, public_key, kDigestData, kVerifyOp);
}

/******************************************************************************/
bool crypto_tiny_verify_hash(const uint8_t hash[32],
		const uint8_t signature[64],
		const uint8_t public_key[64]) {
    return _atecc508a_sign_verify_internal(0, hash, ATCA_SHA_DIGEST_SIZE, (uint8_t *)signature, public_key, kDigestHash, kVerifyOp);
}

/******************************************************************************/
bool atecc508a_dh(const uint8_t public_key[64], uint8_t pre_master_key[32]) {
	return ATCA_SUCCESS == atcab_ecdh(PRIVATE_KEY_SLOT,
			public_key,
			pre_master_key);
}

/******************************************************************************/
#define KDF2_CEIL(x,y) (1 + ((x - 1) / y))
#define MAX_KDF_IN 100
bool atecc508a_kdf2(const uint8_t *  input, size_t inlen, uint8_t * output, size_t olen) {
	size_t counter = 1;
	size_t counter_len;
	uint8_t buf[MAX_KDF_IN + 5];
	uint8_t hash[ATCA_SHA_DIGEST_SIZE];
	uint8_t hash_len = ATCA_SHA_DIGEST_SIZE;
	size_t olen_actual = 0;
	uint8_t counter_string[4];

	// Get KDF parameters
	counter_len = KDF2_CEIL(olen, hash_len);

	// Start hashing
	for(; counter <= counter_len; ++counter) {
		counter_string[0] = (uint8_t)((counter >> 24) & 255);
		counter_string[1] = (uint8_t)((counter >> 16) & 255);
		counter_string[2] = (uint8_t)((counter >> 8)) & 255;
		counter_string[3] = (uint8_t)(counter & 255);

		memcpy(buf, input, inlen);
		memcpy(&buf[inlen], counter_string, 4);

		if (olen_actual + hash_len <= olen) {
			atcab_sha(inlen + 4, buf, output + olen_actual);
			olen_actual += hash_len;
		} else {
			atcab_sha(inlen + 4, buf, hash);
			memcpy(output + olen_actual, hash, olen - olen_actual);
			olen_actual = olen;
		}
	}

	return true;
}

/******************************************************************************/
uint8_t remove_padding_size(uint8_t * data, size_t data_sz) {
	uint8_t i, padding_val;

	padding_val = data[data_sz - 1];

	if (padding_val < 2 || padding_val > 15 || data_sz < padding_val) return 0;

	for (i = 0; i < padding_val; ++i) {
		if (data[data_sz - 1 - i] != padding_val) {
			return 0;
		}
	}

	return padding_val;
}

/******************************************************************************/
bool create_hmac(uint8_t key[32], const uint8_t * data, size_t data_sz, uint8_t hmac[32]) {
	uint8_t tmp[32];
	uint8_t ipad[64];
	uint8_t opad[64];
	const uint8_t * p = data;
	size_t i;

	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);

	for (i = 0; i < 32; i++) {
		ipad[i] = (uint8_t)(ipad[i] ^ key[i]);
		opad[i] = (uint8_t)(opad[i] ^ key[i]);
	}

	if (ATCA_SUCCESS != atcab_sha_start()
			|| ATCA_SUCCESS != atcab_sha_update(64, ipad)) return false;

	for (i = 0; i < (data_sz >> 6 /* div 64 */); i++, p += 64) {
		if (ATCA_SUCCESS != atcab_sha_update(64, p)) return false;
	}

	return ATCA_SUCCESS == atcab_sha_end(tmp, data_sz & 0x3F /* mod 64 */, p)
			&& ATCA_SUCCESS == atcab_sha_start()
			&& ATCA_SUCCESS == atcab_sha_update(64, opad)
			&& ATCA_SUCCESS == atcab_sha_end(hmac, 32, tmp);
}

/******************************************************************************/
bool crypto_tiny_encrypt(const uint8_t * data, size_t data_sz,
						   const uint8_t public_key[ATCA_PUB_KEY_SIZE],
						   uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz) {

    uint8_t iv[32];
    uint8_t pre_master_key[32];
    uint8_t master_key[48];     // 16 bytes - key and 32 bytes for hmac
    uint8_t data_for_enc[256];
    uint8_t hmac[32];
    uint8_t encrypted_data[256];
    size_t encrypted_data_sz;
    uint8_t data_rest;
    uint8_t * own_public_key;

    if (ATCA_SUCCESS != atcab_random(iv)) return false;

    encrypted_data_sz = ((data_sz >> 4) + 1) << 4;

    if (!encrypted_data_sz || encrypted_data_sz > sizeof(data_for_enc)
			|| !atecc508a_dh(public_key, pre_master_key)
			|| !atecc508a_kdf2(pre_master_key,
                    			32,
								master_key,
								sizeof(master_key))) return false;

    memcpy(data_for_enc, data, data_sz);
    data_rest = 16 - (data_sz & 0x0F);
    memset(&data_for_enc[encrypted_data_sz - data_rest], data_rest, data_rest);

    aes_encrypt(encrypted_data,
            	data_for_enc,
				encrypted_data_sz,
                master_key,
                iv);

    if (!create_hmac(&master_key[16],
    				 encrypted_data,
					 encrypted_data_sz,
                     hmac)) return false;

    crypto_tiny_own_public_key(&own_public_key);

    return tiny_cryptogram_create(encrypted_data,
    							 data_sz,
								 encrypted_data_sz,
								 iv,
								 hmac,
								 own_public_key,
								 cryptogram,
								 buf_sz,
								 cryptogram_sz);
}

/******************************************************************************/
bool crypto_tiny_decrypt(
#if !defined(CRYPTO_ATMEL)
		const uint8_t * private_key, size_t private_key_sz,
#endif
		const uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz) {
    uint8_t * public_key;
    uint8_t * encrypted_data;
    size_t encrypted_data_sz;

    uint8_t pre_master_key[32];
    uint8_t master_key[48];

    uint8_t * iv;
    uint8_t * hmac;

    if (!tiny_cryptogram_parse(cryptogram, cryptogram_sz,
								 &public_key,
								 &iv,
								 &hmac,
								 &encrypted_data,
								 &encrypted_data_sz,
								 decrypted_data_sz)) {
        return false;
    }


    if (!atecc508a_dh(public_key, pre_master_key)
    		|| !atecc508a_kdf2(pre_master_key,
                                 	 	32,
										master_key,
										sizeof(master_key))) return false;

    uint8_t encrypted_data_copy[encrypted_data_sz];
    memcpy(encrypted_data_copy, encrypted_data, encrypted_data_sz);

    aes_decrypt(decrypted_data,
    			encrypted_data_copy,
				encrypted_data_sz,
                master_key,
                iv);

    return true;
}

/******************************************************************************/
bool atecc508a_load_data(uint8_t slot_id, uint8_t * data, size_t data_sz) {
//RRR	bool res = false;
	int i, blocks;
	uint8_t buf[32];
	uint8_t * p = data;
	size_t need_sz = data_sz, cp_sz;

#if 0
	if (data_sz > 72) return false;
#endif

	blocks = data_sz >> 5;
	if (data_sz & 0x1F) {
		++blocks;
	}

	for (i = 0; i < blocks; ++i) {
		if (ATCA_SUCCESS != atcab_read_zone(ATCA_ZONE_DATA, slot_id, i, 0, buf, 32)) {
			return false;
		}
		cp_sz = need_sz > 32 ? 32 : need_sz;
		memcpy(p, buf, cp_sz);
		need_sz -= cp_sz;
		p += cp_sz;
	}

	return true;
}

/******************************************************************************/
bool crypto_tiny_random(uint8_t key[32]) {
	return ATCA_SUCCESS == atcab_random(key);
}

#endif // CRYPTO_ATMEL
