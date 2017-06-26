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
 * @file atecc508a_provision.h
 * @brief Create keys and certificate for ATECC508A.
 */

#ifndef atecc508a_provision_h
#define atecc508a_provision_h

#include <stdint.h>
#include <stdbool.h>
#include <virgil/atecc508a/data.h>

/**
 * @brief Create keys and certificate.
 * @result true if done successfully.
 */

bool atecc508a_start_provisioning();

bool atecc508a_set_manufacture(uint32_t manufacture);
bool atecc508a_set_serial(serial_number_t *serial);
bool atecc508a_set_model(uint32_t model);
bool atecc508a_set_parts_count(uint8_t parts_count);
bool atecc508a_set_part(uint8_t part, uint32_t number);

bool atecc508a_save_device_info();

bool atecc508a_save_key(uint8_t slot_id, const uint8_t * key, size_t key_sz);
bool atecc508a_signature(uint8_t slot_id, const uint8_t * signature, size_t signature_sz);


#endif /* atecc508a_provision_h */
