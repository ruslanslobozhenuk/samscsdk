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
 * @file crypto.c
 * @brief Wrapper for cryptographic functionality.
 *
 * Key pair creation, encryption/decryption and signing plus sign checking.
 *
 ******************************************************************************/

#if defined(CRYPTO_MBEDTLS)

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>

#include <virgil/crypto.h>
#include <virgil/crypto_tiny.h>
#include <virgil/converters/converters_mbedtls.h>

#define HASH_TYPE MBEDTLS_MD_SHA256
#define EC_CURVE  MBEDTLS_ECP_DP_SECP256R1

int entropy_source(void *data, unsigned char *output, size_t len, size_t *olen);

/***************************************************************************//**
* @brief Create pk_context from public key
*
*******************************************************************************/
bool create_context_for_public_key(mbedtls_pk_context * ctx,
                                          const uint8_t * public_key,
                                          size_t public_key_sz) {
    mbedtls_pk_context res;
    mbedtls_pk_init(&res);
    if (0 == mbedtls_pk_parse_public_key(&res,
                                         (const unsigned char *) public_key,
                                         public_key_sz)) {
        *ctx = res;
        return true;
    }
    return false;
}

/***************************************************************************//**
* @brief Create pk_context from private key
*
*******************************************************************************/
bool create_context_for_private_key(mbedtls_pk_context * ctx,
                                           const uint8_t * private_key,
                                           size_t private_key_sz) {
    mbedtls_pk_context res;
    mbedtls_pk_init(&res);
    if (0 == mbedtls_pk_parse_key(&res,
                                  (const unsigned char *) private_key,
                                  private_key_sz,
                                  NULL,
                                  0)) {
        *ctx = res;
        return true;
    }
    return false;
}

/***************************************************************************//**
 * @brief Entropy source based on nrf_drv_rng. For Virgil crypto library.
 *
 * @param[in]	data			not used
 * @param[out]	output		result entropy data
 * @param[in]	len			need size entropy
 * @param[out]	olen			real size of result entropy data
 *
 * @result 0 if done successfully and error code in other case.
 * .
 ******************************************************************************/
int entropy_source(void *data, unsigned char *output, size_t len, size_t *olen) {
	((void) data);
	if (!output || !len || !olen) return 0;
#if 0
	*olen = 0;
	uint32_t err_code;
	uint8_t bytes_available = 0;
	err_code = nrf_drv_rng_bytes_available(&bytes_available);
	APP_ERROR_CHECK(err_code);

	*olen = len > bytes_available ? bytes_available : len;
	if (bytes_available > 0) {
		err_code = nrf_drv_rng_rand(output, *olen);
		APP_ERROR_CHECK(err_code);
	} else {
		LOG("RNG is empty !");
	}
#else
	*olen = len > 0xFF ? 0xFF : len;
	for (int i = 0; i < *olen; ++i) {
		output[i] = rand() % 0xFF;
	}
#endif

	return 0;
}

/******************************************************************************/
bool crypto_init() {
	return true;
}

/******************************************************************************/
bool crypto_create_key_pair(uint8_t * private_key, size_t private_key_buf_sz, size_t * private_key_sz, uint8_t * public_key, size_t public_key_buf_sz, size_t * public_key_sz) {
    const char *pers = "gen_keypair";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;
    bool res = false;
    int res_sz;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_ctx);

    if (0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)
        && 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
        		mbedtls_entropy_func,//entropy_source,
                                      &entropy,
                                      (const unsigned char *)pers,
                                      strlen(pers))
        && 0 == mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
        && 0 == mbedtls_ecp_gen_key(EC_CURVE, mbedtls_pk_ec(pk_ctx),
                                    mbedtls_ctr_drbg_random, &ctr_drbg)) {
        
            res_sz = mbedtls_pk_write_pubkey_der(&pk_ctx, public_key, public_key_buf_sz);
            if (res_sz > 0) {
                if (public_key_buf_sz > res_sz) {
                    memmove(public_key, &public_key[public_key_buf_sz - res_sz], res_sz);
                }
                *public_key_sz = res_sz;
                
                res_sz = mbedtls_pk_write_key_der(&pk_ctx, private_key, private_key_buf_sz);
                
                if (res_sz > 0) {
                    if (private_key_buf_sz > res_sz) {
                        memmove(private_key, &private_key[private_key_buf_sz - res_sz], res_sz);
                    }
                    *private_key_sz = res_sz;
                    
                    res = true;
                }
            }
    }
    
    return res;
}

/******************************************************************************/
bool crypto_encrypt(const uint8_t * recipient_id, size_t recipient_id_sz,
        			const uint8_t * public_key, size_t public_key_sz,
					uint8_t * data, size_t data_sz,
					uint8_t * cryptogram, size_t buf_sz, size_t * cryptogram_sz) {
    bool res = false;
    const char *pers = "encrypt";
    
    uint8_t * data_with_pad = 0;
    size_t data_with_pad_sz;
    size_t pad_sz;
    
    uint8_t master_key[16];
    size_t master_key_sz;
    
    uint8_t iv[16];
    size_t iv_sz;
    
    uint8_t * encrypted_master_key = 0;
    size_t encrypted_master_key_sz;
    
    uint8_t * encrypted_data = 0;
    size_t encrypted_data_sz;
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context public_key_ctx;
    
    *cryptogram_sz = 0;
    
    if (!recipient_id || !public_key || !public_key_sz || !data || !data_sz || !buf_sz) {
        return false;
    }
  
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&public_key_ctx);
    
    pad_sz = 16 - (data_sz % 16);
    if (!pad_sz) {
        pad_sz = 16;
    }
    data_with_pad_sz = data_sz + pad_sz;
    
    data_with_pad = malloc(data_with_pad_sz);
    memcpy(data_with_pad, data, data_sz);
    memset(&data_with_pad[data_sz], pad_sz, pad_sz);
    
    encrypted_master_key_sz = 1024 + sizeof(master_key);
    encrypted_master_key = malloc(encrypted_master_key_sz);
    
    encrypted_data_sz = data_with_pad_sz;
    encrypted_data = malloc(encrypted_data_sz);
    
    if (0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)
        
        && 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
                                      mbedtls_entropy_func,
                                      &entropy,
                                      (const unsigned char *)pers,
                                      strlen(pers))
        
        && create_context_for_public_key(&public_key_ctx, public_key, public_key_sz)
        
        && 0 == entropy_source(0, (unsigned char *)master_key, sizeof(master_key), &master_key_sz)
        
        && 0 == entropy_source(0, (unsigned char *)iv, sizeof(iv), &iv_sz)
        
        && 0 == mbedtls_pk_encrypt(&public_key_ctx,
                                   (unsigned char *)master_key, sizeof(master_key),
                                   (unsigned char *)encrypted_master_key, &encrypted_master_key_sz, encrypted_master_key_sz,
                                   mbedtls_ctr_drbg_random, &ctr_drbg)
        
        && crypto_aes_encrypt(data_with_pad, data_with_pad_sz, master_key, iv, encrypted_data)
        
        && virgil_cryptogram_create_mbedtls(recipient_id, recipient_id_sz,
                                    encrypted_master_key, encrypted_master_key_sz,
                                    encrypted_data, encrypted_data_sz,
                                    iv,
									cryptogram, buf_sz, cryptogram_sz)) {
        res = true;
    }
    
#if 0
    char print_buf[1024];
    size_t print_buf_sz = 1024;
    mbedtls_base64_encode(print_buf, sizeof(print_buf), &print_buf_sz, cryptogram, *cryptogram_sz);
    printf("%s\n", print_buf);
#endif
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&public_key_ctx);
    
    free(data_with_pad);
    free(encrypted_master_key);
    free(encrypted_data);
    
    return res;
}

/******************************************************************************/
bool crypto_decrypt(const uint8_t * recipient_id, size_t recipient_id_sz, const uint8_t * private_key, size_t private_key_sz,
		uint8_t * cryptogram, size_t cryptogram_sz,
		uint8_t * decrypted_data, size_t buf_sz, size_t * decrypted_data_sz) {
    
    bool res = false;
    const char *pers = "decrypt";

    uint8_t buf[1024];
    size_t tmp_sz;

    uint8_t master_key[16];
    
    uint8_t * iv;
    
    uint8_t * encrypted_master_key = 0;
    size_t encrypted_master_key_sz;
    
    uint8_t * encrypted_data = 0;
    size_t encrypted_data_sz;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context private_key_ctx;
    
    *decrypted_data_sz = 0;
    
    if (!recipient_id || !recipient_id[0] || !private_key || !private_key_sz || !cryptogram || !cryptogram_sz || !buf_sz) {
        return false;
    }
    
    if (!virgil_cryptogram_parse_mbedtls(cryptogram, cryptogram_sz,
                                 recipient_id, recipient_id_sz,
                                 &iv,
                                 &encrypted_master_key, &encrypted_master_key_sz,
                                 &encrypted_data, &encrypted_data_sz)) {
        return false;
    }
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&private_key_ctx);

    if (0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)
        
        && 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
                                      mbedtls_entropy_func,
                                      &entropy,
                                      (const unsigned char *)pers,
                                      strlen(pers))
        
        && create_context_for_private_key(&private_key_ctx, private_key, private_key_sz)
        
        && 0 == mbedtls_pk_decrypt(&private_key_ctx,
                                   (unsigned char *)encrypted_master_key, encrypted_master_key_sz,
                                   (unsigned char *)buf, &tmp_sz, sizeof(buf),
                                   mbedtls_ctr_drbg_random, &ctr_drbg)
        
        && memcpy(master_key, buf, sizeof(master_key))
        
        && crypto_aes_decrypt(encrypted_data, encrypted_data_sz, master_key, iv, buf)) {

        *decrypted_data_sz = encrypted_data_sz - buf[encrypted_data_sz - 1];
        memcpy(decrypted_data, buf, *decrypted_data_sz);
        
        res = true;
    }
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&private_key_ctx);
    
    return res;
}

/******************************************************************************/
static bool _sign_internal(const uint8_t * private_key, size_t private_key_sz, const uint8_t * data, size_t data_sz, uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz, bool is_hash) {
    
    bool res = false;
    bool hash_ready;
    const char *pers = "sign";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context private_key_ctx;
    
    uint8_t mbedtls_sign[MBEDTLS_MPI_MAX_SIZE];
    size_t mbedtls_sign_sz;
    
    uint8_t hash[
#if HASH_TYPE == MBEDTLS_MD_SHA256
                 32
#else
                 128
#endif
                 ];
    
    if (!private_key || !private_key_sz || !data || !data_sz
        || !sign_data || buf_sz < 100) {
    	return false;
    }
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&private_key_ctx);
    
    if (is_hash) {
        memcpy(hash, data, sizeof(hash));
        hash_ready = true;
    } else {
        hash_ready = crypto_hash(data, data_sz, hash);
    }
    
    if (hash_ready
        && create_context_for_private_key(&private_key_ctx, private_key, private_key_sz)
        && 0 == mbedtls_entropy_add_source(&entropy, entropy_source, 0, 1, MBEDTLS_ENTROPY_SOURCE_STRONG)
        && 0 == mbedtls_ctr_drbg_seed(&ctr_drbg,
                                      mbedtls_entropy_func,
                                      &entropy,
                                      (const unsigned char *)pers,
                                      strlen(pers))
        && 0 == mbedtls_pk_sign(&private_key_ctx, HASH_TYPE, hash, 0,
                                mbedtls_sign, &mbedtls_sign_sz,
                                mbedtls_ctr_drbg_random, &ctr_drbg)
        && mbedtls_sign_to_virgil(HASH_TYPE,
                                  mbedtls_sign, mbedtls_sign_sz,
                                  sign_data, buf_sz, sign_data_sz)) {
        res = true;
    }
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&private_key_ctx);
    
    return res;
}

/******************************************************************************/
bool crypto_sign(const uint8_t * private_key, size_t private_key_sz, const uint8_t * data, size_t data_sz, uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz) {
    return _sign_internal(private_key, private_key_sz,
                          data, data_sz,
                          sign_data, buf_sz, sign_data_sz,
                          false);
}

/******************************************************************************/
static bool _verify_internal(const uint8_t * public_key, size_t public_key_sz,
		const uint8_t * sign, size_t sign_sz, const uint8_t * data,
		size_t data_sz, bool is_hash) {
    bool res = false;
    bool hash_ready;
    const uint8_t * mbedtls_sign;
    size_t mbedtls_sign_sz;
    
    mbedtls_pk_context public_key_ctx;
    uint8_t hash[
#if HASH_TYPE == MBEDTLS_MD_SHA256
                 32
#else
                 128
#endif
                 ];
    
    if (!public_key || !public_key_sz || !sign || !sign_sz || !data || !data_sz) {
		return false;
	}
    
    mbedtls_pk_init(&public_key_ctx);
    
    if (is_hash) {
        memcpy(hash, data, sizeof(hash));
        hash_ready = true;
    } else {
        hash_ready = crypto_hash(data, data_sz, hash);
    }
    
    if (hash_ready
        && create_context_for_public_key(&public_key_ctx, public_key, public_key_sz)
        && virgil_sign_to_mbedtls(sign, sign_sz,
                                   &mbedtls_sign, &mbedtls_sign_sz)
        && 0 == mbedtls_pk_verify(&public_key_ctx, HASH_TYPE,
                                  hash, 0,
                                  (const unsigned char *)mbedtls_sign, mbedtls_sign_sz)) {
            res = true;
    }
    
    mbedtls_pk_free(&public_key_ctx);
    
	return res;
}

/******************************************************************************/
bool crypto_verify(const uint8_t * public_key, size_t public_key_sz,
                   const uint8_t * sign, size_t sign_sz, const uint8_t * data,
                   size_t data_sz) {
    return _verify_internal(public_key, public_key_sz,
                            sign, sign_sz,
                            data, data_sz,
                            false);
}

/******************************************************************************/
bool crypto_aes_encrypt(uint8_t * input, size_t size, const uint8_t key[16], const uint8_t iv[16], uint8_t * output) {
    bool res = true;
    mbedtls_aes_context ctx;
    unsigned char iv_tmp[16];
    
    memcpy(iv_tmp, iv, 16);
    
    mbedtls_aes_init(&ctx);

    res &= 0 == mbedtls_aes_setkey_enc(&ctx, key, 128);

    res &= 0 == mbedtls_aes_crypt_cbc(&ctx,
                          MBEDTLS_AES_ENCRYPT,
                          size,
                          iv_tmp,
                          input,
                          output);

    mbedtls_aes_free(&ctx);
    
    return res;
}

/******************************************************************************/
bool crypto_aes_decrypt(uint8_t * input, size_t size, const uint8_t key[16], const uint8_t iv[16], uint8_t * output) {
    bool res = true;
    mbedtls_aes_context ctx;
    unsigned char iv_tmp[16];
    
    memcpy(iv_tmp, iv, 16);
    
    mbedtls_aes_init(&ctx);

    res &= 0 == mbedtls_aes_setkey_dec(&ctx, key, 128);

    res &= 0 == mbedtls_aes_crypt_cbc(&ctx,
                                      MBEDTLS_AES_DECRYPT,
                                      size,
                                      iv_tmp,
                                      input,
                                      output);

    mbedtls_aes_free(&ctx);
    
    return res;
}

/******************************************************************************/
bool crypto_hash(const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
	return crypto_tiny_hash(data, data_sz, hash);
}

/******************************************************************************/
bool crypto_hash_start(void ** ctx) {
#if HASH_TYPE == MBEDTLS_MD_SHA256
    
    mbedtls_sha256_context * sha256_ctx = malloc(sizeof(mbedtls_sha256_context));
    mbedtls_sha256_init(sha256_ctx);
    mbedtls_sha256_starts(sha256_ctx, 0);
    *ctx = (void *)sha256_ctx;
    
    return true;
#else
    return false;
#endif
}

/******************************************************************************/
bool crypto_hash_update(void * ctx, const uint8_t * data, size_t data_sz) {
#if HASH_TYPE == MBEDTLS_MD_SHA256
    
    if (!ctx) return false;
    
    mbedtls_sha256_context * sha256_ctx = (mbedtls_sha256_context *)ctx;
    mbedtls_sha256_update(sha256_ctx, (uint8_t *)data, data_sz);
    
    return true;
#else
    return false;
#endif
}

/******************************************************************************/
bool crypto_hash_finish(void * ctx, const uint8_t * data, size_t data_sz, uint8_t hash[32]) {
#if HASH_TYPE == MBEDTLS_MD_SHA256
    
    if (!ctx) return false;
    
    mbedtls_sha256_context * sha256_ctx = (mbedtls_sha256_context *)ctx;

    if (data && data_sz) {
    	mbedtls_sha256_update(sha256_ctx, (uint8_t *)data, data_sz);
    }

    mbedtls_sha256_finish(sha256_ctx, (unsigned char *)hash);
    mbedtls_sha256_free(sha256_ctx);
    free(sha256_ctx);
    
    return true;
#else
    return false;
#endif
}

/******************************************************************************/
bool crypto_sign_hash(const uint8_t * private_key, size_t private_key_sz, const uint8_t hash[32], uint8_t * sign_data, size_t buf_sz, size_t * sign_data_sz) {
    return _sign_internal(private_key, private_key_sz,
                          hash, 32,
                          sign_data, buf_sz, sign_data_sz,
                          true);
}

/******************************************************************************/
bool crypto_verify_hash(const uint8_t * public_key, size_t public_key_sz, const uint8_t * sign, size_t sign_sz, const uint8_t hash[32]) {
    return _verify_internal(public_key, public_key_sz,
                            sign, sign_sz,
                            hash, 32,
                            true);
}

#endif //CRYPTO_MBEDTLS
