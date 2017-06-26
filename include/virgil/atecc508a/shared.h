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

#if defined (ATECC508A_SHARED)

#ifndef shared_h
#define shared_h

#include <stdint.h>
#include <virgil/atecc508a/data.h>
#include <virgil/aes/aes.h>

#include "atca_command.h"
#include "basic/atca_basic.h"
#include "atca_command.h"

typedef struct {
	ATCADevice _gDevice;
	ATCACommand _gCommandObj;
	ATCAIface _gIface;
	uint8_t _own_public_key[
#if defined (ATECC508A_SHARED)
							64
#else
							100
#endif
							];
	size_t _own_public_key_sz;
	uint8_t _device_id[32];
	size_t _device_id_sz;
	struct atca_command commands;
	struct atca_device device;
	struct atca_iface interface;
#if defined (ATCA_HAL_I2C)
	void * * m_i2c_handle;
	uint32_t m_i2c_handle_buf[0x20];
	volatile int m_result;
	uint8_t m_i2c_buf[200];
#endif
	state_t* aes_state;
	uint8_t aes_round_key[176];
	uint8_t* aes_key;
	uint8_t* aes_iv;
} atecc508a_ctx_t;

extern atecc508a_ctx_t atecc508a_ctx;

#endif // shared_h

#endif // ATECC508A_SHARED
