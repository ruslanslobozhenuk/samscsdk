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
 * @file crypto_tiny_mbedtlsl.h
 */

#if defined(CRYPTO_MBEDTLS)

#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>

#include <virgil/crypto.h>
#include <virgil/crypto_tiny.h>
#include <virgil/converters/converters_mbedtls.h>
#include <virgil/converters/converters_tiny.h>

static uint8_t m_session_key[CRYPTO_SESSION_KEY_SZ];
static bool m_key_ready = false;

bool create_context_for_public_key(mbedtls_pk_context * ctx,
		const uint8_t * public_key,
		size_t public_key_sz);

bool create_context_for_private_key(mbedtls_pk_context * ctx,
        const uint8_t * private_key,
        size_t private_key_sz);

int entropy_source(void *data, unsigned char *output, size_t len, size_t *olen);

/******************************************************************************/
bool crypto_tiny_init() {
	return true;
}

/******************************************************************************/
bool crypto_tiny_is_ready() {
	return true;
}

/******************************************************************************/
bool crypto_tiny_own_id(uint8_t ** own_id, size_t * own_id_sz) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_own_public_key(uint8_t * key[64]) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
#if HASH_TYPE == MBEDTLS_MD_SHA256
	mbedtls_sha256(data, data_sz, hash, 0);
	return true;
#else
	return false;
#endif
}

/******************************************************************************/
bool crypto_tiny_hash_start() {
	return false;
}

/******************************************************************************/
bool crypto_tiny_hash_update(const uint8_t * data, size_t data_sz) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_hash_finish(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_sign(const uint8_t * private_key, size_t private_key_sz, const uint8_t * data, size_t data_sz, uint8_t signature[64]) {
	uint8_t full_signature[VIRGIL_SIGNATURE_MAX_SIZE];
	size_t full_signature_sz;

	return crypto_sign(private_key, private_key_sz, data, data_sz, full_signature, VIRGIL_SIGNATURE_MAX_SIZE, &full_signature_sz)
			&& virgil_sign_to_tiny(full_signature, full_signature_sz, signature);
}

/******************************************************************************/
bool crypto_tiny_sign_hash(const uint8_t * private_key, size_t private_key_sz, const uint8_t hash[32], uint8_t signature[64]) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_verify(const uint8_t * data, size_t data_sz,
		const uint8_t signature[64],
		const uint8_t public_key[64]) {

	uint8_t full_public_key[VIRGIL_PUBLIC_KEY_MAX_SIZE];
	size_t full_public_key_sz = VIRGIL_PUBLIC_KEY_MAX_SIZE;

	uint8_t full_signature[VIRGIL_SIGNATURE_MAX_SIZE];
	size_t full_signature_sz = VIRGIL_SIGNATURE_MAX_SIZE;

	if (!tiny_pubkey_to_virgil((uint8_t *)public_key, full_public_key, &full_public_key_sz)) return false;
	if (!tiny_sign_to_virgil((uint8_t *)signature, full_signature, &full_signature_sz)) return false;

	return crypto_verify(full_public_key, full_public_key_sz,
			full_signature, full_signature_sz,
			data, data_sz);
}

/******************************************************************************/
bool crypto_tiny_verify_hash(const uint8_t hash[32],
		const uint8_t signature[64],
		const uint8_t public_key[64]) {
	return false;
}

/******************************************************************************/
bool crypto_tiny_encrypt(const uint8_t * data, size_t data_sz,
		const uint8_t public_key[64],
		uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz) {
	bool res = false;
	const char *pers = "encrypt";

	uint8_t iv[16];
	size_t iv_sz;

	uint8_t * encrypted_data = 0;
	size_t encrypted_data_sz;

	uint8_t * public_key_tiny_parsed;

	uint8_t full_public_key[VIRGIL_PUBLIC_KEY_MAX_SIZE];
	size_t full_public_key_sz = VIRGIL_PUBLIC_KEY_MAX_SIZE;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context public_key_ctx;

	*cryptogram_sz = 0;

	if (!public_key ||!data || !data_sz || !buf_sz) {
		return false;
	}

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_pk_init(&public_key_ctx);

	encrypted_data_sz = 1024 + data_sz;
	encrypted_data = malloc(encrypted_data_sz);

	uint8_t * public_key_parsed;
	uint8_t * iv_parsed;
	uint8_t * hmac_parsed;
	uint8_t * encrypted_data_parsed;
	size_t encrypted_data_sz_parsed;

	if (!tiny_pubkey_to_virgil((uint8_t *)public_key, full_public_key, &full_public_key_sz)) return false;

	if (0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)

			&& 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
					mbedtls_entropy_func,
					&entropy,
					(const unsigned char *)pers,
					strlen(pers))

					&& create_context_for_public_key(&public_key_ctx, full_public_key, full_public_key_sz)

					&& 0 == entropy_source(0, (unsigned char *)iv, sizeof(iv), &iv_sz)

					&& 0 == mbedtls_pk_encrypt(&public_key_ctx,
							(unsigned char *)data, data_sz,
							(unsigned char *)encrypted_data, &encrypted_data_sz, encrypted_data_sz,
							mbedtls_ctr_drbg_random, &ctr_drbg)

							&& mbedtls_cryptogram_parse_low_level(encrypted_data, encrypted_data_sz,
									&public_key_tiny_parsed,
									&iv_parsed,
									&hmac_parsed,
									&encrypted_data_parsed,
									&encrypted_data_sz_parsed)

									&& tiny_cryptogram_create(encrypted_data_parsed,
											data_sz,
											encrypted_data_sz_parsed,
											iv_parsed,
											hmac_parsed,
											public_key_tiny_parsed,
											cryptogram,
											buf_sz,
											cryptogram_sz)) {
	
#if 0
            char print_buf[1024];
            size_t print_buf_sz = 1024;
            mbedtls_base64_encode(print_buf, sizeof(print_buf), &print_buf_sz,
                                  //cryptogram, *cryptogram_sz
                                  encrypted_data, encrypted_data_sz
                                  );
            printf("%s\n", print_buf);
#endif
        res = true;
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_pk_free(&public_key_ctx);

	free(encrypted_data);

	return res;
}

/******************************************************************************/
bool crypto_tiny_decrypt(const uint8_t * private_key, size_t private_key_sz,
		const uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz) {

	uint8_t * public_key_parsed;
	uint8_t * iv_parsed;
	uint8_t * hmac_parsed;
	uint8_t * encrypted_data_parsed;
	size_t encrypted_data_sz_parsed;
	size_t decrypted_data_sz_parsed;

	uint8_t full_public_key[VIRGIL_PUBLIC_KEY_MAX_SIZE];
	size_t full_public_key_sz = VIRGIL_PUBLIC_KEY_MAX_SIZE;

	bool res = false;
	const char *pers = "decrypt";

	uint8_t buf[1024];
	size_t tmp_sz;

	uint8_t * encrypted_data = 0;
	size_t encrypted_data_sz;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_pk_context private_key_ctx;

	*decrypted_data_sz = 0;

	if (
#if !defined(CRYPTO_ATMEL)
			!private_key || !private_key_sz ||
#endif
			!cryptogram || !cryptogram_sz || !buf_sz) {
		return false;
	}

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_pk_init(&private_key_ctx);

	uint8_t mbedtls_cryptogram[1024];
	size_t mbedtls_cryptogram_sz;

	if (tiny_cryptogram_parse(cryptogram, cryptogram_sz,
			&public_key_parsed,
			&iv_parsed,
			&hmac_parsed,
			&encrypted_data_parsed,
			&encrypted_data_sz_parsed,
			&decrypted_data_sz_parsed)

			&& tiny_pubkey_to_virgil(public_key_parsed, full_public_key, &full_public_key_sz)

			&& low_level_cryptogram_create_mbedtls(full_public_key, full_public_key_sz,
					encrypted_data_parsed, encrypted_data_sz_parsed,
                    hmac_parsed,
					iv_parsed,
					mbedtls_cryptogram, sizeof(mbedtls_cryptogram), &mbedtls_cryptogram_sz)) {
		if (0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)

				&& 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
						mbedtls_entropy_func,
						&entropy,
						(const unsigned char *)pers,
						strlen(pers))

						&& create_context_for_private_key(&private_key_ctx, private_key, private_key_sz)

						&& 0 == mbedtls_pk_decrypt(&private_key_ctx,
								(unsigned char *)mbedtls_cryptogram, mbedtls_cryptogram_sz,
								(unsigned char *)buf, &tmp_sz, sizeof(buf),
								mbedtls_ctr_drbg_random, &ctr_drbg)) {

			*decrypted_data_sz = tmp_sz;
			memcpy(decrypted_data, buf, *decrypted_data_sz);

			res = true;
		}
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_pk_free(&private_key_ctx);

	return res;
}

/******************************************************************************/
bool crypto_tiny_session_key(uint8_t key[CRYPTO_SESSION_KEY_SZ]) {
	if (!m_key_ready && !crypto_tiny_update_session_key()) {
		return false;
	}
	memcpy(key, m_session_key, CRYPTO_SESSION_KEY_SZ);
	return true;
}

/******************************************************************************/
bool crypto_tiny_update_session_key() {
	size_t res;
	m_key_ready = 0 == entropy_source(0, m_session_key, CRYPTO_SESSION_KEY_SZ, &res)
				&& CRYPTO_SESSION_KEY_SZ == res;

	return m_key_ready;
}

/******************************************************************************/
bool crypto_tiny_random(uint8_t key[32]) {
	size_t res;
	return 0 == entropy_source(0, key, 32, &res);
}

#endif // CRYPTO_MBEDTLS
