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
 * @file atecc508a_data.h
 * @brief Data for ATECC508A.
 */

#ifndef atecc508a_data_h
#define atecc508a_data_h

#include <atcacert/atcacert_def.h>
#include <stdint.h>
#include <atca_command.h>

#define PRIVATE_KEY_SLOT            		0   /**< ATECC508A slot number with private key */
#define SECURE_TRANSFER_KEY_SLOT    		1   /**< ATECC508A slot number with key which used for secure transfer of session key */
#define EXTERNAL_PRIVATE_KEY_SLOT    		2   /**< Slot with external private key (debug mode only) */

#define DEVICE_INFO_SLOT					8	/* Serial number, Model number, Part number */

#define SIGNATURE_SLOT    					10   /**< Signature of own public key (signed using Firmware private key) */

#define FIRMWARE_PUBLIC_KEY_SLOT    		11  /**< Firmware public key */
#define FIRMWARE_PUBLIC_KEY_ALT_SLOT    	12  /**< Firmware public key (alternative) */

#define DEVICE_PUBLIC_KEY_SLOT    			13  /**< Device verification public key */
#define DEVICE_PUBLIC_KEY_ALT_SLOT			14  /**< Device verification public key (alternative) */

#define PARTS_COUNT_MAX						5	/**< Maximum count of parts */

typedef struct {
    uint8_t bytes[ATCA_SHA_DIGEST_SIZE];
} serial_number_t;

// There is no need in pack
typedef struct {
	uint32_t manufacture_number;
	serial_number_t serial_number;
	uint32_t model_number;
	uint8_t parts_count;
	uint32_t part_number[PARTS_COUNT_MAX];
} device_info_t;

extern const uint8_t _access_key[32];

#endif /* atecc508a_data_h */
