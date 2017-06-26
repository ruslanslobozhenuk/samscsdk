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
 * @file converters_tiny_common.c
 * @brief Conversion between virgil and tiny data structures
 */

//#include <virgil/converters/converters_tiny_atmel.h>
#include <string.h>
#include <stdbool.h>

#include <virgil/asn1/asn1.h>
#include <virgil/converters/converters.h>

typedef struct __attribute__((__packed__)) {
	uint8_t public_key[64];
    uint8_t hmac[32];
	uint8_t iv[16];
	uint16_t encrypted_data_sz;
	uint16_t decrypted_data_sz;
} custom_cryptogram_header_t;

static const uint8_t _sha256_oid_sequence[] = {
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00
};

static const uint8_t _pubkey_prefix[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04
};

/******************************************************************************/
bool virgil_sign_to_tiny(const uint8_t * virgil_sign, size_t virgil_sign_sz, uint8_t sign[64]) {
	int pos = 0;
	const uint8_t * p_r = 0;
	size_t r_sz = 0;
	const uint8_t * p_s = 0;
	size_t s_sz = 0;

	if (asn1_step_into(SEQUENCE, &pos, virgil_sign_sz, virgil_sign)
			&& asn1_skip(SEQUENCE, &pos, virgil_sign_sz, virgil_sign)
			&& asn1_step_into(OCTET_STRING, &pos, virgil_sign_sz, virgil_sign)
			&& asn1_step_into(SEQUENCE, &pos, virgil_sign_sz, virgil_sign)
			&& asn1_get_array(INTEGER, &pos, virgil_sign_sz, virgil_sign, &p_r, &r_sz)
			&& asn1_get_array(INTEGER, &pos, virgil_sign_sz, virgil_sign, &p_s, &s_sz)) {

		if (r_sz >= 32 && r_sz <= 34 && 0 == p_r[0]) {
			p_r += r_sz - 32;
			r_sz -= r_sz - 32;
		}

		if (s_sz >= 32 && s_sz <= 34 && 0 == p_s[0]) {
			p_s += s_sz - 32;
			s_sz -= s_sz - 32;
		}

        if (r_sz > 32) return false;
        if (s_sz > 32) return false;
        
        memset(sign, 0, 64);
        
        memcpy(&sign[32 - r_sz], p_r, r_sz);
        memcpy(&sign[64 - s_sz], p_s, s_sz);

		return true;
	}

	return false;
}

/******************************************************************************/
bool tiny_sign_to_virgil(uint8_t sign[64], uint8_t * virgil_sign, size_t * virgil_sign_sz) {
	uint8_t buf[ANS1_BUF_SIZE];
	int pos = ANS1_BUF_SIZE;
	size_t total_sz = 0, el_sz;

	if (!asn1_put_array(INTEGER, &pos, buf, &sign[32], 32, &el_sz, &total_sz)
			|| !asn1_put_array(INTEGER, &pos, buf, sign, 32, &el_sz, &total_sz)
			|| !asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz)
			|| !asn1_put_header(OCTET_STRING, &pos, buf, total_sz, &el_sz, &total_sz)
			|| !asn1_put_raw(&pos,
					buf,
					_sha256_oid_sequence,
					sizeof(_sha256_oid_sequence),
					&el_sz, &total_sz)
					|| !asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz)
					|| (*virgil_sign_sz < total_sz)) return false;

	*virgil_sign_sz = total_sz;
	memcpy(virgil_sign, &buf[pos], total_sz);

	return true;
}

/******************************************************************************/
bool virgil_privkey_to_tiny(const uint8_t * virgil_private_key, size_t virgil_private_key_sz, uint8_t private_key[36]) {
	int pos = 0;
	const uint8_t * key = 0;
	size_t key_sz = 0;

	if (asn1_step_into(SEQUENCE, &pos, virgil_private_key_sz, virgil_private_key)
			&& asn1_skip(INTEGER, &pos, virgil_private_key_sz, virgil_private_key)
			&& asn1_get_array(OCTET_STRING, &pos, virgil_private_key_sz, virgil_private_key, &key, &key_sz)
			&& 32 == key_sz) {

		memset(private_key, 0, 4);
		memcpy(&private_key[4], key, key_sz);

		return true;
	}

	return false;
}

/******************************************************************************/
bool virgil_pubkey_to_tiny_no_copy(const uint8_t * virgil_public_key, size_t virgil_public_key_sz, uint8_t **public_key) {
	int pos = 0;
	const uint8_t * key = 0;
	size_t key_sz = 0;

	if (asn1_step_into(SEQUENCE, &pos, virgil_public_key_sz, virgil_public_key)
			&& asn1_skip(SEQUENCE, &pos, virgil_public_key_sz, virgil_public_key)
			&& asn1_get_array(BIT_STRING, &pos, virgil_public_key_sz, virgil_public_key, &key, &key_sz)) {

		if (key_sz > 66 || key_sz < 64) return false;

		*public_key = (uint8_t *)&key[key_sz - 64];
		return true;
	}

	return false;
}

/******************************************************************************/
bool virgil_pubkey_to_tiny(const uint8_t * virgil_public_key, size_t virgil_public_key_sz, uint8_t public_key[64]) {
	uint8_t * p = 0;

	if (virgil_pubkey_to_tiny_no_copy(virgil_public_key, virgil_public_key_sz, &p) && p) {
		memcpy(public_key, p, 64);
		return true;
	}

	return false;
}

/******************************************************************************/
bool tiny_pubkey_to_virgil(uint8_t public_key[64], uint8_t * virgil_public_key, size_t * virgil_public_key_sz) {
	if (*virgil_public_key_sz < (sizeof(_pubkey_prefix) + 64)) return false;

	memcpy(virgil_public_key, _pubkey_prefix, sizeof(_pubkey_prefix));
	memcpy(&virgil_public_key[sizeof(_pubkey_prefix)], public_key, 64);
	*virgil_public_key_sz = sizeof(_pubkey_prefix) + 64;
	return true;
}

/******************************************************************************/
bool tiny_cryptogram_create(const uint8_t * encrypted_data,
							  size_t decrypted_data_sz,
							  size_t encrypted_data_sz,
							  const uint8_t iv[16],
							  const uint8_t hmac[32],
							  const uint8_t public_key[64],
							  uint8_t * cryptogram,
							  size_t cryptogram_buf_sz,
							  size_t * cryptogram_sz) {
	custom_cryptogram_header_t * header = (custom_cryptogram_header_t *)cryptogram;

#if 0
	if (cryptogram_buf_sz < (sizeof(custom_cryptogram_header_t) + encrypted_data_sz)) {
		return false;
	}
#endif

	*cryptogram_sz = sizeof(custom_cryptogram_header_t) + encrypted_data_sz;

	memcpy(header->public_key, public_key, 64);
	memcpy(header->iv, iv, 16);
    memcpy(header->hmac, hmac, 32);
	header->encrypted_data_sz = encrypted_data_sz;
	header->decrypted_data_sz = decrypted_data_sz;
	memcpy(&cryptogram[sizeof(custom_cryptogram_header_t)], encrypted_data, encrypted_data_sz);

	return true;
}

/******************************************************************************/
bool tiny_cryptogram_parse(const uint8_t * cryptogram, size_t cryptogram_sz,
										uint8_t ** public_key,
										uint8_t ** iv,
										uint8_t ** hmac,
										uint8_t ** encrypted_data,
										size_t * encrypted_data_sz,
										size_t * decrypted_data_sz) {
	custom_cryptogram_header_t * header = (custom_cryptogram_header_t *)cryptogram;
	*public_key = header->public_key;
	*iv = header->iv;
	*encrypted_data_sz = header->encrypted_data_sz;
	*decrypted_data_sz = header->decrypted_data_sz;
    *hmac = header->hmac;
	*encrypted_data = (uint8_t *)cryptogram + sizeof(custom_cryptogram_header_t);

	return true;
}
