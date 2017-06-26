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
 * @file lpc824_i2c_hal.c
 * @brief Hardware abstraction layer.
 *
 ******************************************************************************/

#if defined (ATCA_HAL_I2C) && defined(LPC824)

#include <hal/atca_hal.h>
#include <chip.h>
#include <stdlib.h>
#include <string.h>

#if !defined (VIRGIL_HAL_DEBUG)
//#define VIRGIL_HAL_DEBUG
#endif

#if defined(__TINY__)

#if defined (ATECC508A_SHARED)
#include <virgil/atecc508a/shared.h>
#define m_i2c_handle (atecc508a_ctx.m_i2c_handle)
#define m_i2c_handle_buf (atecc508a_ctx.m_i2c_handle_buf)
#define m_result (atecc508a_ctx.m_result)
#define m_i2c_buf (atecc508a_ctx.m_i2c_buf)
#else
static I2C_HANDLE_T * m_i2c_handle = 0;		/**< Handle for current i2c session */
static uint32_t  m_i2c_handle_buf[0x20];	/**< i2c session data */
static volatile int  m_result;
static uint8_t  m_i2c_buf[512];
#endif

#endif

#define I2C_BITRATE			40000		/**< 20 kbps I2C bit-rate */

#define CMD_WAKE			0x00
#define CMD_SLEEP			0x01
#define CMD_IDLE			0x02
#define CMD_REQUEST			0x03

#define SDA 11
#define SCL 10

extern void sleep_us(uint32_t us);
extern void sleep_ms(uint32_t ms);

/******************************************************************************/
void atca_delay_us(uint32_t delay) {
	sleep_us(delay);
}

/******************************************************************************/
void atca_delay_10us(uint32_t delay) {
	uint32_t val;
	val = 10;
	val *= delay;
	atca_delay_us(val);
}

/******************************************************************************/
void atca_delay_ms(uint32_t delay) {
	sleep_ms(delay);
}

/******************************************************************************/
static void i2c_done(uint32_t result_code, uint32_t n) {
	m_result = (int) result_code;
}

/******************************************************************************/
void atecc508a_i2c_irq() {
	/* Call I2C ISR function in ROM with the I2C handle */
	LPC_I2CD_API->i2c_isr_handler(m_i2c_handle);
}

/******************************************************************************/
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg) {
	/* Enable the clock to the Switch Matrix */
	Chip_Clock_EnablePeriphClock(SYSCTL_CLOCK_SWM);

	/* Connect the I2C_SDA and I2C_SCL signals to port pins(P0.10, P0.11) */
	Chip_SWM_EnableFixedPin(SWM_FIXED_I2C0_SDA);
	Chip_SWM_EnableFixedPin(SWM_FIXED_I2C0_SCL);

#if (I2C_BITRATE > 400000)
	/* Enable Fast Mode Plus for I2C pins */
	Chip_IOCON_PinSetI2CMode(LPC_IOCON, IOCON_PIO10, PIN_I2CMODE_FASTPLUS);
	Chip_IOCON_PinSetI2CMode(LPC_IOCON, IOCON_PIO11, PIN_I2CMODE_FASTPLUS);
#endif

	/* Disable the clock to the Switch Matrix to save power */
	Chip_Clock_DisablePeriphClock(SYSCTL_CLOCK_SWM);

	/* Enable I2C clock and reset I2C peripheral - the boot ROM does not do this */
	Chip_I2C_Init(LPC_I2C);

	/* Setup the I2C handle */
	m_i2c_handle = LPC_I2CD_API->i2c_setup(LPC_I2C_BASE, m_i2c_handle_buf);

#if 0
	if (!m_i2c_handle) {
		return ATCA_EXECUTION_ERROR;
	}
#endif

	/* Set I2C bitrate */
	if (LPC_I2CD_API->i2c_set_bitrate(m_i2c_handle,
			Chip_Clock_GetSystemClockRate(),
			I2C_BITRATE) != LPC_OK) {
		return ATCA_EXECUTION_ERROR;
	}

	/* Enable the interrupt for the I2C */
	NVIC_EnableIRQ(I2C_IRQn);

	return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS hal_i2c_post_init(ATCAIface iface) {
	return ATCA_SUCCESS;
}

/******************************************************************************/
static ATCA_STATUS i2c_send(ATCAIface iface, uint8_t command, uint8_t *txdata, int txlength) {
	I2C_PARAM_T param;
	I2C_RESULT_T result;

//	if ((txlength + 2) > sizeof(m_i2c_buf)) return ATCA_BAD_PARAM;

	ATCAIfaceCfg * cfg = atgetifacecfg(iface);

	txlength++;         		// account for word address value byte.
	m_i2c_buf[0] = cfg->atcai2c.slave_address;

	if (txlength > 1) {
		// From ATMEL code
		txdata[0] = command;   	// insert the Word Address Value, Command token
		// ~From ATMEL code
		memcpy(&m_i2c_buf[1], txdata, txlength);
	} else {
		m_i2c_buf[1] = command;
	}

	/* Setup I2C parameters for number of bytes with stop - appears as follows on bus:
			   Start - address7 or address10upper - ack
			   (10 bits addressing only) address10lower - ack
			   value 1 - ack
			   value 2 - ack - stop */
	param.num_bytes_send    = txlength + 1;
	param.buffer_ptr_send   = m_i2c_buf;
	param.num_bytes_rec     = 0;
	param.stop_flag         = 1;
	param.func_pt           = i2c_done;

	/* Set timeout (much) greater than the transfer length */
	LPC_I2CD_API->i2c_set_timeout(m_i2c_handle, 1000000);

	/* Do master write transfer */
	m_result = -1;

	/* Function is non-blocking, returned error should be LPC_OK, but isn't checked here */
	LPC_I2CD_API->i2c_master_transmit_intr(m_i2c_handle, &param, &result);

	/* Sleep until transfer is complete, but allow IRQ to wake system to handle I2C IRQ */
	while (m_result == -1) {
		__WFI();
	}

	/* Completed without errors ? */
	if (LPC_OK == m_result && result.n_bytes_sent == param.num_bytes_send) {
		return ATCA_SUCCESS;
	}

	return ATCA_TX_TIMEOUT;
}
/******************************************************************************/
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength) {
	return i2c_send(iface, CMD_REQUEST, txdata, txlength);
}

/******************************************************************************/
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength) {
	I2C_PARAM_T param;
	I2C_RESULT_T result;
	ErrorCode_t error_code = -1;
	int i;
	ATCA_STATUS status = ATCA_RX_NO_RESPONSE;

	if ((*rxlength + 2) > sizeof(m_i2c_buf)) return ATCA_BAD_PARAM;

	ATCAIfaceCfg *cfg = atgetifacecfg(iface);

	for (i = 0; i < cfg->rx_retries; ++i) {
		memset(m_i2c_buf, 0, *rxlength + 2);
		memset(&result, 0, sizeof(result));
		m_i2c_buf[0] = cfg->atcai2c.slave_address;

		/* Setup I2C paameters for number of bytes with stop - appears as follows on bus:
				   Start - address7 or address10upper - ack
				   (10 bits addressing only) address10lower - ack
				   value 1 (read) - ack
				   value 2 read) - ack - stop */
		param.num_bytes_send    = 0;
		param.num_bytes_rec     = *rxlength + 1;
		param.buffer_ptr_rec    = m_i2c_buf;
		param.stop_flag         = 1;
		param.func_pt           = i2c_done;

		/* Do master read transfer */
		m_result = -1;

		/* Set timeout (much) greater than the transfer length */
		LPC_I2CD_API->i2c_set_timeout(m_i2c_handle, 100000);

		/* Function is non-blocking, returned error should be LPC_OK, but isn't checked here */
		error_code = LPC_I2CD_API->i2c_master_receive_intr(m_i2c_handle, &param, &result);

		/* Sleep until transfer is complete, but allow IRQ to wake system to handle I2C IRQ */
		while (m_result == -1) {
			__WFI();
		}

		/* Completed without erors? */
		if (LPC_OK == error_code && result.n_bytes_recd > 1) {
			memset(rxdata, 0, *rxlength);
			*rxlength = result.n_bytes_recd - 1;
			if (*rxlength > m_i2c_buf[1]) {
				*rxlength = m_i2c_buf[1];
			}
			memcpy(rxdata, &m_i2c_buf[1], *rxlength);
			status = ATCA_SUCCESS;
			break;
		} else {
			atca_delay_ms(1);
		}
	}

	if (ATCA_SUCCESS != status) {
		*rxlength = 0;
	}

	return status;
}

/******************************************************************************/
ATCA_STATUS hal_i2c_wake(ATCAIface iface) {
	I2C_PARAM_T param;
	I2C_RESULT_T result;
	uint16_t rxlength;

	int i;
	static const uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };

	uint8_t response[4];
	ATCA_STATUS status;

	memset(response, 0, 4);

	for (i = 0; i < 3; ++i) {
		status = ATCA_WAKE_FAILED;
		rxlength = sizeof(response);

		// Generate Wake Token
		m_i2c_buf[0] = 0x00;

		param.num_bytes_send    = 1;
		param.buffer_ptr_send   = m_i2c_buf;
		param.num_bytes_rec     = 0;
		param.stop_flag         = 1;

		LPC_I2CD_API->i2c_set_timeout(m_i2c_handle, 1000000);
		LPC_I2CD_API->i2c_master_transmit_poll(m_i2c_handle, &param, &result);

		atca_delay_us(700);

		// Receive Wake Response
		status = hal_i2c_receive(iface, response, &rxlength);
		if (status == ATCA_SUCCESS) {
			// Compare response with expected_response
			if (memcmp(response, expected_response, 4) != 0) {
				status = ATCA_WAKE_FAILED;
			}
		}

		if (ATCA_SUCCESS == status) {
			return ATCA_SUCCESS;
		}
	}
	return ATCA_WAKE_FAILED;
}

/******************************************************************************/
ATCA_STATUS hal_i2c_idle(ATCAIface iface) {
	return i2c_send(iface, CMD_IDLE, 0, 0);
}

/******************************************************************************/
ATCA_STATUS hal_i2c_sleep(ATCAIface iface) {
	return i2c_send(iface, CMD_SLEEP, 0, 0);
}

/******************************************************************************/
ATCA_STATUS hal_i2c_release(void *hal_data) {
	if (m_i2c_handle) {
		Chip_I2C_DeInit(LPC_I2C);

		Chip_Clock_EnablePeriphClock(SYSCTL_CLOCK_SWM);

		Chip_SWM_DisableFixedPin(SWM_FIXED_I2C0_SDA);
		Chip_SWM_DisableFixedPin(SWM_FIXED_I2C0_SCL);

		Chip_Clock_DisablePeriphClock(SYSCTL_CLOCK_SWM);
	}
	return ATCA_SUCCESS;
}

#endif
