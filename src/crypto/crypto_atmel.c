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
 * @file crypto_atmel.h
 * @brief Wrapper for ATECC508A.
 */

#if defined(CRYPTO_ATMEL)

#include <virgil/crypto.h>

#include <atca_cfgs.h>
#include <basic/atca_basic.h>
#include <crypto/hashes/sha2_routines.h>
#include <atcacert/atcacert_def.h>

#include <virgil/converters/converters.h>
#include <virgil/converters/converters_tiny.h>
#include <virgil/atecc508a/data.h>
#include <virgil/aes/aes.h>
#include <virgil/crypto_tiny.h>

#if defined (ATECC508A_SHARED)
#define _own_public_key 	(atecc508a_ctx._own_public_key)
#define _own_public_key_sz 	(atecc508a_ctx._own_public_key_sz)
#define _device_id 			(atecc508a_ctx._device_id)
#define _device_id_sz 		(atecc508a_ctx._device_id_sz)
#else
static uint8_t _own_public_key[100];
static size_t _own_public_key_sz = 0;
//RRR static uint8_t _device_id[32];
//RRR static size_t _device_id_sz = 0;
#endif

extern bool atecc508a_own_id(uint8_t ** own_id, size_t * own_id_sz);
extern bool atecc508a_dh(const uint8_t public_key[64], uint8_t pre_master_key[32]);
extern bool atecc508a_kdf2(const uint8_t *  input, size_t inlen, uint8_t * output, size_t olen);
extern uint8_t remove_padding_size(uint8_t * data, size_t data_sz);
extern bool create_hmac(uint8_t key[32], const uint8_t * data, size_t data_sz, uint8_t hmac[32]);

/******************************************************************************/
bool crypto_init() {
	_own_public_key_sz = 0;
	return crypto_tiny_init();
}

/******************************************************************************/
bool crypto_is_ready() {
	return crypto_tiny_is_ready();
}

/******************************************************************************/
bool crypto_own_id(uint8_t ** own_id, size_t * own_id_sz) {
	return crypto_tiny_own_id(own_id, own_id_sz);
}

/******************************************************************************/
static bool atecc508a_own_public_key() {
	uint8_t internal_key[64];
	size_t sz = sizeof(_own_public_key);

	if (!_own_public_key_sz) {
		if (ATCA_SUCCESS != atcab_get_pubkey(PRIVATE_KEY_SLOT, internal_key)) {
			return false;
		}
		tiny_pubkey_to_virgil(internal_key, _own_public_key, &sz);
		_own_public_key_sz = sz;
	}

	return true;
}

/******************************************************************************/
bool crypto_create_key_pair(uint8_t * private_key,
		size_t private_key_buf_sz,
		size_t * private_key_sz,
		uint8_t * public_key,
		size_t public_key_buf_sz,
		size_t * public_key_sz) {

//RRR	uint8_t internal_key[64];
//RRR	size_t sz = sizeof(_own_public_key);

	*public_key = 0;
	*public_key_sz = 0;

	if (!atecc508a_own_public_key()) return false;

	if (public_key_buf_sz < _own_public_key_sz) return false;

	memcpy(public_key, _own_public_key, _own_public_key_sz);
	*public_key_sz = _own_public_key_sz;

	return true;
}

/******************************************************************************/
bool crypto_encrypt(const uint8_t * recipient_id, size_t recipient_id_sz,
		const uint8_t * public_key, size_t public_key_sz,
		uint8_t * data, size_t data_sz,
		uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz) {

	uint8_t rnd[32], buf[32];
	uint8_t pre_master_key[32];
	uint8_t master_key[48];     // 16 bytes - key and 32 bytes for hmac
	uint8_t encrypted_key[32];
	uint8_t data_for_enc[256];
	uint8_t hmac[32];
	uint8_t encrypted_data[256];
	size_t encrypted_data_sz;
	uint8_t * recipient_pub_key;
	uint8_t * iv, * shared_key;
	uint8_t data_rest;

	if (!atecc508a_own_public_key()) return false;
	if (ATCA_SUCCESS != atcab_random(rnd)) return false;

	iv = rnd;
	shared_key = &rnd[16];

	encrypted_data_sz = ((data_sz >> 4) + 1) << 4;

	if (!encrypted_data_sz || encrypted_data_sz > sizeof(data_for_enc)
			|| !virgil_pubkey_to_tiny_no_copy(public_key, public_key_sz, &recipient_pub_key)
			|| !atecc508a_dh(recipient_pub_key, pre_master_key)
			|| !atecc508a_kdf2(pre_master_key,
					32,
					master_key,
					sizeof(master_key))) return false;

	memcpy(buf, shared_key, 16);
	memset(&buf[16], 16, 16);

	aes_encrypt(encrypted_key,
			buf,
			32,
			master_key,
			iv);

	memcpy(data_for_enc, data, data_sz);
	data_rest = 16 - (data_sz & 0x0F);
	memset(&data_for_enc[encrypted_data_sz - data_rest], data_rest, data_rest);

	aes_encrypt(encrypted_data,
			data_for_enc,
			encrypted_data_sz,
			shared_key,
			iv);

	if (!create_hmac(&master_key[16],
			encrypted_key,
			32,
			hmac)) return false;

	*cryptogram_sz = buf_sz;
	return virgil_cryptogram_create_low_level(recipient_id, recipient_id_sz,
			encrypted_data_sz,
			encrypted_data,
			iv,
			encrypted_key,
			iv,
			hmac,
			_own_public_key, _own_public_key_sz,
			cryptogram, cryptogram_sz);
}

/******************************************************************************/
bool crypto_decrypt(const uint8_t * recipient_id, size_t recipient_id_sz,
		const uint8_t * private_key, size_t private_key_sz,
		uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz) {
	uint8_t * encrypted_key;
	uint8_t encrypted_key_data[16];
	uint8_t * public_key;
	uint8_t decrypted_key[64];
	uint8_t encrypted_data_copy[256];
	uint8_t * encrypted_data;
	size_t encrypted_data_sz;

	uint8_t pre_master_key[32];
	uint8_t master_key[48];

	uint8_t * iv_key;
	uint8_t * iv_data;

	if (!virgil_cryptogram_parse_low_level(cryptogram, cryptogram_sz,
			recipient_id, recipient_id_sz,
			&public_key,
			&iv_key,
			&encrypted_key,
			&iv_data,
			&encrypted_data,
			&encrypted_data_sz)) {
		return false;
	}

	if (!atecc508a_dh(public_key, pre_master_key)
			|| !atecc508a_kdf2(pre_master_key,
					32,
					master_key,
					sizeof(master_key))) return false;

	memcpy(encrypted_key_data, encrypted_key, 16);
	aes_decrypt(decrypted_key,
			encrypted_key_data,
			16,
			master_key,
			iv_key);

	if (*decrypted_data_sz < encrypted_data_sz) return false;

	*decrypted_data_sz = encrypted_data_sz;

	if (encrypted_data_sz > sizeof(encrypted_data_copy)) return false;
	memcpy(encrypted_data_copy, encrypted_data, encrypted_data_sz);
	aes_decrypt(decrypted_data,
			encrypted_data_copy,
			encrypted_data_sz,
			decrypted_key,
			iv_data);

	*decrypted_data_sz -= remove_padding_size(decrypted_data, *decrypted_data_sz);

	return true;
}

/******************************************************************************/
static bool _atecc508a_sign_internal(uint8_t slot,
		const uint8_t * data, size_t data_sz,
		uint8_t * signature, size_t * signature_sz,
		digest_t digest_type) {
	uint8_t hash[ATCA_SHA_DIGEST_SIZE];
	uint8_t _internal_sign[ATCA_SIG_SIZE];

	if (kDigestData == digest_type) {
		if (!crypto_hash(data, data_sz, hash)) {
			return false;
		}
	} else {
		memcpy(hash, data, ATCA_SHA_DIGEST_SIZE);
	}

	if (ATCA_SUCCESS == atcab_sign(slot,
			hash,
			_internal_sign)) {
		return tiny_sign_to_virgil(_internal_sign, signature, signature_sz);
	}

	return false;
}

/******************************************************************************/
static bool _atecc508a_verify_internal(const uint8_t * data, size_t data_sz,
		const uint8_t * signature, size_t signature_sz,
		const uint8_t * public_key, size_t public_key_sz,
		digest_t digest_type) {
	bool is_verified = false;
	uint8_t hash[ATCA_SHA_DIGEST_SIZE];
	uint8_t _internal_sign[ATCA_SIG_SIZE];
	uint8_t * _internal_pubkey;

	if (!virgil_sign_to_tiny(signature, signature_sz, _internal_sign)
			|| !virgil_pubkey_to_tiny_no_copy(public_key, public_key_sz, &_internal_pubkey)) {
		return false;
	}

	if (kDigestData == digest_type) {
		if (!crypto_hash(data, data_sz, hash)) {
			return false;
		}
	} else {
		memcpy(hash, data, ATCA_SHA_DIGEST_SIZE);
	}

	if (ATCA_SUCCESS == atcab_verify_extern(hash,
			_internal_sign,
			_internal_pubkey,
			&is_verified)) {
		return is_verified;
	}

	return false;
}

/******************************************************************************/
bool crypto_sign(const uint8_t * private_key, size_t private_key_sz,
		const uint8_t * data, size_t data_sz,
		uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz) {
	*sign_data_sz = buf_sz;
	return _atecc508a_sign_internal(PRIVATE_KEY_SLOT, data, data_sz, sign_data, sign_data_sz, kDigestData);
}

/******************************************************************************/
bool crypto_sign_hash(const uint8_t * private_key, size_t private_key_sz,
		const uint8_t hash[32],
		uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz) {
	*sign_data_sz = buf_sz;
	return _atecc508a_sign_internal(PRIVATE_KEY_SLOT, hash, ATCA_SHA_DIGEST_SIZE, sign_data, sign_data_sz, kDigestHash);
}

/******************************************************************************/
bool crypto_verify(const uint8_t * public_key, size_t public_key_sz,
		const uint8_t * sign, size_t sign_sz,
		const uint8_t * data, size_t data_sz) {
	return _atecc508a_verify_internal(data, data_sz, sign, sign_sz, public_key, public_key_sz, kDigestData);
}

/******************************************************************************/
bool crypto_verify_hash(const uint8_t * public_key, size_t public_key_sz,
		const uint8_t * sign, size_t sign_sz,
		const uint8_t hash[32]) {
	return _atecc508a_verify_internal(hash, ATCA_SHA_DIGEST_SIZE, sign, sign_sz, public_key, public_key_sz, kDigestHash);
}

/******************************************************************************/
bool crypto_aes_encrypt(uint8_t * input, size_t size,
		const uint8_t key[16], const uint8_t iv[16],
		uint8_t * output) {
#if defined(AES_STANDALONE)
	aes_encrypt(output, input, size, key, iv);
	return true;
#else
	return false;
#endif
}

/******************************************************************************/
bool crypto_aes_decrypt(uint8_t * input, size_t size,
		const uint8_t key[16], const uint8_t iv[16],
		uint8_t * output) {
#if defined(AES_STANDALONE)
	aes_decrypt(output, input, size, key, iv);
	return true;
#else
	return false;
#endif
}

/******************************************************************************/
bool crypto_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
	return crypto_tiny_hash(data, data_sz, hash);
}

/******************************************************************************/
bool crypto_hash_start(void ** ctx) {
	return crypto_tiny_hash_start();
}

/******************************************************************************/
bool crypto_hash_update(void * ctx, const uint8_t * data, size_t data_sz) {
	return crypto_tiny_hash_update(data, data_sz);
}

/******************************************************************************/
bool crypto_hash_finish(void * ctx, const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
	return crypto_tiny_hash_finish(data, data_sz, hash);
}


#if 0

/******************************************************************************/
static bool load_data(uint8_t slot_id, uint8_t * data, size_t data_sz) {
	bool res = false;
	int i, blocks;
	uint8_t buf[32];
	uint8_t * p = data;
	size_t need_sz = data_sz, cp_sz;

	if (data_sz > 72) return false;

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
result_t atecc508a_public_key(uint8_t slot, uint8_t * key, size_t * key_sz) {
	if (*key_sz < 95) return ERR_GENERAL;
	if (!load_data(slot, &key[*key_sz - ATCA_PUB_KEY_SIZE], ATCA_PUB_KEY_SIZE))  return ERR_GENERAL;
	if (!atecc508a_pubkey_to_virgil(&key[*key_sz - ATCA_PUB_KEY_SIZE], key, key_sz)) return ERR_GENERAL;
	return RES_OK;
}

#endif

#endif // CRYPTO_ATMEL
