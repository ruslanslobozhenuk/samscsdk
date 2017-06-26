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
 * @file atecc508a_provision.c
 * @brief Create keys and certificate for ATECC508A.
 */

#if defined(CRYPTO_ATMEL)

#include <stdint.h>
#include <atca_cfgs.h>
#include <basic/atca_basic.h>
#include <atcacert/atcacert_def.h>

#include <virgil/atecc508a/data.h>
#include <virgil/atecc508a/provision.h>
#include <virgil/asn1/asn1.h>

device_info_t m_device_info;		/**< Current device info */
bool m_defice_info_ready = false;

/** Helper macros to result of operation */
#define CHECK(RES, OPERATION) if (!(RES = (0 == OPERATION))) return RES;

static const uint8_t _configdata[128] = {
		0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00,  0x04, 0x05, 0x06, 0x07, 0xEE, 0x00, 0x01, 0x00,
		0xC0, 0x00, 0x55, 0x00,

		0x87, 0x20,	// Slot 0  - Own key pair
		0x8F, 0x0F,	// Slot 1  - Key for secure data exchange (between LPC824 and ATECC508A)
		0x83, 0x61, // Slot 2  - External private key (debug mode only)
		0xC4, 0x44, // Slot 3  - not used
		0x8F, 0x0F, // Slot 4  - not used
		0x8F, 0x8F,	// Slot 5  - not used
		0x9F, 0x8F,	// Slot 6  - not used
		0x83, 0x64,	// Slot 7  - not used
		0x00, 0x61,	// Slot 8  - Device info structure (Serial number, Model number, Part number - biggest slot - 416 bytes)
		0x00, 0x61,	// Slot 9  - not used
		0x00, 0x61,	// Slot 10 - Signature of own public key (signed using Device private key)
		0x00, 0x61,	// Slot 11 - Firmware public key
		0x00, 0x61,	// Slot 12 - Firmware public key (alternative)
		0x00, 0x61,	// Slot 13 - Device public key
		0x00, 0x61,	// Slot 14 - Device public key (alternative)
		0x0F, 0x0F,	// Slot 15 - system use

		// Counter[0]
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		// Counter[1]
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		// LastKeyUse
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

		0x00, 0x00, 0x00, 0x00,

		// Lock bits for each slot
		0xFF, 0xFF,

		// RFU
		0x00, 0x00,

		// X509format
		0x00, 0x00, 0x00, 0x00,

		// KeyConfig
		0x33, 0x00, // 0
		0x3C, 0x00, // 1
		0x33, 0x00, // 2
		0x1C, 0x00, // 3
		0x3C, 0x00, // 4
		0x1C, 0x00, // 5
		0x1C, 0x00, // 7
		0x1C, 0x00, // 8
		0x1C, 0x00, // 9
		0x1C, 0x00, // 10
		0x1C, 0x00, // 11
		0x1C, 0x00, // 12
		0x1C, 0x00, // 12
		0x1C, 0x00, // 13
		0x1C, 0x00, // 14
		0x3C, 0x00  // 15
};

/******************************************************************************/
static bool prepare_configuration() {
	bool res = false;
	bool is_locked = false;
	uint8_t config64[64];
	uint8_t lock_response;
	uint8_t device_public_key[ATCA_PUB_KEY_SIZE];

	atcab_sleep();

	CHECK(res, atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked));

	if (!is_locked) {
		CHECK(res, atcab_write_ecc_config_zone(_configdata));
		CHECK(res, atcab_lock_config_zone(&lock_response));
	}

	// Read the first 64 bytes of the config zone to get the slot config at least
	CHECK(res, atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 0, &config64[0], 32));
	CHECK(res, atcab_read_zone(ATCA_ZONE_CONFIG, 0, 1, 0, &config64[32], 32));
	CHECK(res, atcab_is_locked(LOCK_ZONE_DATA, &is_locked));

	if (!is_locked) {
		CHECK(res, atcab_write_zone(DEVZONE_DATA, SECURE_TRANSFER_KEY_SLOT, 0, 0, _access_key, sizeof(_access_key)));
		CHECK(res, atcab_lock_data_zone(&lock_response));
	}

	CHECK(res, atcab_genkey(PRIVATE_KEY_SLOT, device_public_key));

	return true;
}

/******************************************************************************/
static bool set_data(uint8_t slot_id, const uint8_t * data, size_t data_sz) {
	bool res = false;
	int i, blocks;
	const uint8_t * p = data;

	if (!data || data_sz > 72) return false;

	blocks = data_sz >> 5;
	if (data_sz & 0x1F) {
		++blocks;
	}

	for (i = 0; i < blocks; ++i, p += 32) {
		CHECK(res, atcab_write_enc(slot_id, i, p, _access_key, SECURE_TRANSFER_KEY_SLOT));
	}

	return true;
}

/******************************************************************************/
bool atecc508a_start_provisioning() {
	return prepare_configuration();
}

/******************************************************************************/
bool atecc508a_set_manufacture(uint32_t manufacture) {
	m_device_info.manufacture_number = manufacture;
	return true;
}

/******************************************************************************/
bool atecc508a_set_serial(serial_number_t *serial) {
	if (!serial) return false;
	memcpy(&m_device_info.serial_number, serial, sizeof(serial_number_t));
	return true;
}

/******************************************************************************/
bool atecc508a_set_model(uint32_t model) {
	m_device_info.model_number = model;
	return true;
}

/******************************************************************************/
bool atecc508a_set_parts_count(uint8_t parts_count) {
	if (parts_count > PARTS_COUNT_MAX) return false;
	m_device_info.parts_count = parts_count;
	return true;
}

/******************************************************************************/
bool atecc508a_set_part(uint8_t part, uint32_t number) {
	if (part >= m_device_info.parts_count) return false;
	m_device_info.part_number[part] = number;
	return true;
}

/******************************************************************************/
bool atecc508a_save_device_info() {
	return set_data(DEVICE_INFO_SLOT, (uint8_t *)&m_device_info, sizeof(m_device_info));
}

/******************************************************************************/
bool atecc508a_save_key(uint8_t slot_id, const uint8_t * key, size_t key_sz) {
	uint8_t * atecc508a_pubkey;

	return virgil_pubkey_to_tiny_no_copy(key, key_sz, &atecc508a_pubkey)
			&& set_data(slot_id, atecc508a_pubkey, 64);
}

/******************************************************************************/
bool atecc508a_signature(uint8_t slot_id, const uint8_t * signature, size_t signature_sz) {
	uint8_t tiny_sign[64];

	return virgil_sign_to_tiny(signature, signature_sz, tiny_sign)
				&& set_data(slot_id, tiny_sign, 64);
}

#endif // CRYPTO_ATMEL
