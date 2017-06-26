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
 * @file asn1-converters.c
 * @brief Conversion between virgil asn1 structures and plain data for atecc508a
 */

#include <virgil/asn1/asn1.h>
#include <virgil/converters/converters.h>
#include <virgil/converters/converters_tiny.h>
#include <string.h>

static const uint8_t _aes128_cbc[] = {
    0x30, 0x1D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
    0x02, 0x04, 0x10
};

static const uint8_t _pkcs7_data[] = {
    0x30, 0x2A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07,
    0x01
};

static const uint8_t _hmac[] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static const uint8_t _hash_info[] = {
    0x30, 0x18, 0x06, 0x07, 0x28, 0x81, 0x8C, 0x71, 0x02, 0x05, 0x02, 0x30,
    0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00
};

static const uint8_t _ec_type_info[] = {
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static const uint8_t _enveloped_data_oid[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
};

/******************************************************************************/
bool virgil_cryptogram_parse_low_level(const uint8_t * virgil_encrypted_data, size_t virgil_encrypted_data_sz,
							 const uint8_t * recipient_id, size_t recipient_id_sz,
                             uint8_t ** public_key,
                             uint8_t ** iv_key,
                             uint8_t ** encrypted_key,
                             uint8_t ** iv_data,
                             uint8_t ** encrypted_data,
                             size_t * encrypted_data_sz) {
    
    int pos = 0, saved_pos, set_pos = 0;
    size_t _sz, ar_sz, asn1_sz;
    const uint8_t * _data, * p_ar = 0;
    
    // Recipient id should present
    if (!recipient_id || !recipient_id_sz) return false;
    
    _sz = virgil_encrypted_data_sz;
    _data = virgil_encrypted_data;
    
    if (asn1_step_into(SEQUENCE, &pos, _sz, _data)
        && asn1_skip(INTEGER, &pos, _sz, _data)
        && asn1_step_into(SEQUENCE, &pos, _sz, _data)
        && asn1_skip(OID, &pos, _sz, _data)
        && asn1_step_into(ZERO_TAG, &pos, _sz, _data)
        && asn1_step_into(SEQUENCE, &pos, _sz, _data)
        && asn1_skip(INTEGER, &pos, _sz, _data)) {
    
        set_pos = pos;
        if (!asn1_step_into(SET, &pos, _sz, _data)) return false;
        
        while(true) {
            saved_pos = pos;
            
            if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_skip(INTEGER, &pos, _sz, _data)) return false;
            if (!asn1_step_into(ZERO_TAG, &pos, _sz, _data)) return false;
            if (!asn1_step_into(OCTET_STRING, &pos, _sz, _data)) return false;
            
            // Find out need recipient
            if (0 != memcmp(&_data[pos], recipient_id, recipient_id_sz)) {
                pos = saved_pos;
                if (!asn1_skip(SEQUENCE, &pos, _sz, _data)) return false;
                continue;
            }
            
            pos += recipient_id_sz;
            if (!asn1_skip(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_step_into(OCTET_STRING, &pos, _sz, _data)) return false;
            if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_skip(INTEGER, &pos, _sz, _data)) return false;
            
            // Read public key
            if (!virgil_pubkey_to_tiny_no_copy(&_data[pos], 100, public_key)) return false;
            
            if (!asn1_skip(SEQUENCE, &pos, _sz, _data)) return false;
            
            
            if (!asn1_skip(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_skip(SEQUENCE, &pos, _sz, _data)) return false;
            
            if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
            if (!asn1_skip(OID, &pos, _sz, _data)) return false;
            
            // Get IV array
            if (!asn1_get_array(OCTET_STRING,
                                &pos, _sz, _data,
                                &p_ar,
                                &ar_sz)) return false;
            
            if (ar_sz != 16) return false;
            *iv_key = (uint8_t *)p_ar;
            // ~ Get IV array
            
            // Get encrypted key
            if (!asn1_get_array(OCTET_STRING,
                                &pos, _sz, _data,
                                &p_ar,
                                &ar_sz)) return false;
            
            if (ar_sz > 32) return false;
            *encrypted_key = (uint8_t *)p_ar;
            // ~ Get encrypted key
            
            pos = set_pos;
            if (!asn1_skip(SET, &pos, _sz, _data)) return false;
            break;
        }
        
        if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
        if (!asn1_skip(OID, &pos, _sz, _data)) return false;
        
        if (!asn1_step_into(SEQUENCE, &pos, _sz, _data)) return false;
        if (!asn1_skip(OID, &pos, _sz, _data)) return false;
        
        
        // Get IV for data (AES)
        if (!asn1_get_array(OCTET_STRING,
                            &pos, _sz, _data,
                            &p_ar,
                            &ar_sz)) return false;
        
        if (ar_sz != 16) return false;
        *iv_data = (uint8_t *)p_ar;
        
        // Read encrypted data
        asn1_sz = asn1_get_size(0, _data);
        if (_sz <= asn1_sz) return false;
        *encrypted_data_sz = _sz - asn1_sz;
        
        if (!*encrypted_data_sz || *encrypted_data_sz > 1024) return false;
        *encrypted_data = (uint8_t *)&_data[asn1_sz];
        
        return true;
    }
    
    return false;
}

/******************************************************************************/
bool virgil_cryptogram_create_low_level(const uint8_t * recipient_id, size_t recipient_id_sz,
                              size_t encrypted_data_sz,
                              const uint8_t * encrypted_data,
                              const uint8_t * iv_data,
                              const uint8_t * encrypted_key,
                              const uint8_t * iv_key,
                              const uint8_t * hmac,
                              const uint8_t * public_key, size_t public_key_sz,
							  uint8_t * cryptogram, size_t * cryptogram_sz) {
    
    uint8_t buf[ANS1_BUF_SIZE];
    int pos = ANS1_BUF_SIZE;
    size_t total_sz = 0, pkcs7_data_sz = 0, el_sz;
    
    // Put encrypted data
    if (!asn1_put_raw(&pos, buf, encrypted_data, encrypted_data_sz, &el_sz, 0)) return false;
    
    // PKCS #7 data
    if (!asn1_put_raw(&pos, buf, iv_data, 16, &el_sz, &total_sz)
    		|| !asn1_put_raw(&pos, buf, _aes128_cbc, sizeof(_aes128_cbc), &el_sz, &total_sz)
			|| !asn1_put_raw(&pos, buf, _pkcs7_data, sizeof(_pkcs7_data), &el_sz, &total_sz)) return false;
    
    pkcs7_data_sz = total_sz;
    
    // AES128-CBC encrypted key
    if (!asn1_put_array(OCTET_STRING, &pos, buf, encrypted_key, 32, &el_sz, &total_sz)
    		|| !asn1_put_raw(&pos, buf, iv_key, 16, &el_sz, &total_sz)
			|| !asn1_put_raw(&pos, buf, _aes128_cbc, sizeof(_aes128_cbc), &el_sz, &total_sz)
			|| !asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz)) return false;
    
    // HMAC
    if (!asn1_put_raw(&pos, buf, hmac, 32, &el_sz, &total_sz)
    		||!asn1_put_raw(&pos, buf, _hmac, sizeof(_hmac), &el_sz, &total_sz)) return false;
    
    // hash info
    if (!asn1_put_raw(&pos, buf, _hash_info, sizeof(_hash_info), &el_sz, &total_sz)) return false;
    
    // public key
    if (!asn1_put_raw(&pos, buf, public_key, public_key_sz, &el_sz, &total_sz)) return false;
    
    // integer
    if (!asn1_put_uint8(&pos, buf, 0, &el_sz, &total_sz)) return false;
    
    // wrap with sequence
    if (!asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz)) return false;
    
    // wrap with octet string
    if (!asn1_put_header(OCTET_STRING, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz)) return false;
    
    // EC type info
    if (!asn1_put_raw(&pos, buf, _ec_type_info, sizeof(_ec_type_info), &el_sz, &total_sz)) return false;
    
    // Recipient ID
    if (!asn1_put_array(OCTET_STRING, &pos, buf, recipient_id, recipient_id_sz, &el_sz, &total_sz)) return false;
    
    // Zero element
    if (!asn1_put_header(ZERO_TAG, &pos, buf, el_sz, &el_sz, &total_sz)) return false;
    
    // Integer ver
    if (!asn1_put_uint8(&pos, buf, 2, &el_sz, &total_sz)) return false;
    
    // Wrap with sequence
    if (!asn1_put_header(SEQUENCE, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz)) return false;
    
    // Wrap with set
    if (!asn1_put_header(SET, &pos, buf, total_sz - pkcs7_data_sz, &el_sz, &total_sz)) return false;
    
    // Integer ver
    if (!asn1_put_uint8(&pos, buf, 2, &el_sz, &total_sz)) return false;
    
    // Wrap with sequence
    if (!asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz)) return false;
    
    // Wrap with zero tag
    if (!asn1_put_header(ZERO_TAG, &pos, buf, total_sz, &el_sz, &total_sz)) return false;
    
    // PKCS #7 enveloped data
    if (!asn1_put_raw(&pos, buf, _enveloped_data_oid, sizeof(_enveloped_data_oid), &el_sz, &total_sz)) return false;
    
    // Wrap with sequence
    if (!asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz)) return false;
    
    // Integer
    if (!asn1_put_uint8(&pos, buf, 0, &el_sz, &total_sz)) return false;
    
    // Wrap with sequence
    if (!asn1_put_header(SEQUENCE, &pos, buf, total_sz, &el_sz, &total_sz)) return false;
    
    if (*cryptogram_sz < total_sz) return false;

    *cryptogram_sz = total_sz + encrypted_data_sz;
    memcpy(cryptogram, &buf[pos], *cryptogram_sz);

    return true;
}
