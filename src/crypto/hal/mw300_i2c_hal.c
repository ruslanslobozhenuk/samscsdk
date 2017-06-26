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
 * @file mw300_i2c_hal.c
 * @brief Hardware abstraction layer.
 *
 ******************************************************************************/

#if defined (ATCA_HAL_I2C) && defined(MARVELL_88MW302)

#include <hal/atca_hal.h>
#include "mdev.h"
#include "mdev_gpio.h"
#include "mdev_pinmux.h"
#include "mdev_i2c.h"
//#include <wm_os.h>
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
static mdev_t * m_i2c_handle = 0;		/**< Handle for current i2c session */
static mdev_t * m_pinmux_dev = 0;       /**< Handle for pinmux config */
static uint32_t  m_i2c_handle_buf[0x20];	/**< i2c session data */
static volatile int  m_result;
static uint8_t  m_i2c_buf[512];
#endif

#endif

#define I2C_PORT_NUM        I2C1_PORT
#define I2C_BITRATE			40000		/**< 20 kbps I2C bit-rate */
#define I2C_SLAVE_ADDR      0xC0

#define CMD_WAKE			0x00
#define CMD_SLEEP			0x01
#define CMD_IDLE			0x02
#define CMD_REQUEST			0x03

#define I2C1_SDA 25
#define I2C1_SCL 26
//#define I2C1_SDA 16
//#define I2C1_SCL 27

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
//static void i2c_done(uint32_t result_code, uint32_t n) {
//	m_result = (int) result_code;
//}

static void i2c_done(I2C_INT_Type type, void *data) {
	m_result = WM_SUCCESS;
}

/******************************************************************************/
void atecc508a_i2c_irq() {
	/* Call I2C ISR function in ROM with the I2C handle */
	i2c_drv_set_callback(m_i2c_handle, i2c_done, NULL);
}

/******************************************************************************/
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg) {
	/* Enable the clock to the Switch Matrix */
	pinmux_drv_init();
	m_pinmux_dev = pinmux_drv_open("MDEV_PINMUX");
//	gpio_drv_init();
//	m_gpio_dev = gpio_drv_open("MDEV_GPIO");
	i2c_drv_init(I2C1_PORT);

	/* Connect the I2C_SDA and I2C_SCL signals to port pins(P0.10, P0.11) */
	pinmux_drv_setfunc(m_pinmux_dev, I2C1_SDA, PINMUX_FUNCTION_2);
	pinmux_drv_setfunc(m_pinmux_dev, I2C1_SCL, PINMUX_FUNCTION_2);

#if (I2C_BITRATE > 400000)
	/* Enable Fast Mode Plus for I2C pins */
	//i2c_drv_set_clkcnt(I2C1_PORT,600,1300);
#endif

	/* Disable the clock to the Switch Matrix to save power */
	// Chip_Clock_DisablePeriphClock(SYSCTL_CLOCK_SWM);

	/* Enable I2C clock and reset I2C peripheral - the boot ROM does not do this */
	// Chip_I2C_Init(LPC_I2C);

	/* Set timeouts in case of read/write failures, e.g.
	 * slave is absent on the bus. Delay values are approximate and
	 * can be tuned as per requirement. */
	i2c_drv_timeout(I2C1_PORT, 1000, 1000);

	/* Setup the I2C handle */
	/* I2C1 is configured as master */
	m_i2c_handle = i2c_drv_open(I2C1_PORT, I2C_SLAVEADR(0xC0 >> 1));
	//RRR m_i2c_handle = i2c_drv_open(I2C1_PORT, I2C_SLAVEADR(0xC0));

#if 0
	if (!m_i2c_handle) {
		return ATCA_EXECUTION_ERROR;
	}
#endif

	/* Set I2C bitrate */
	/** Set I2C driver clock(SCL) configuration
	 *
	 * This is optional call to change I2C CLK frequency.  By default the
	 * clock settings are set for standard loading conditions.
	 * I2C clock frequency may deviate from the standard 100K/ 400K due to bus
	 * loading. User may use this API to tune the I2C clk frequency.
	 * @note  This call should be made after i2c_drv_init() and
	 *        before i2c_drv_open() to over-write default configuration.
	 *
	 * @param[in] i2c_id I2C ID of the driver
	 * @param[in] hightime min high time for I2C SCL (clock line) in nanoseconds
	 * @param[in] lowtime min low time for I2C SCL (clock line) in nanoseconds
	 * Reducing the hightime or lowtime would increase the SCL frequency
	 * Default values for 100K are
	 * HCNT: 4000	LCNT:4700
	 * Default values for 400K are
	 * HCNT: 600	LCNT:1300
	 */
	 //i2c_drv_set_clkcnt(I2C1_PORT,4000,4700);

	/* Enable the interrupt for the I2C */
	// NVIC_EnableIRQ(I2C_IRQn);

	return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS hal_i2c_post_init(ATCAIface iface) {
	return ATCA_SUCCESS;
}

/******************************************************************************/
static ATCA_STATUS i2c_send(ATCAIface iface, uint8_t command, uint8_t *txdata, int txlength) {
//	I2C_PARAM_T param;
//	I2C_RESULT_T result;
	uint32_t txStatus;
	int sentLen;

	if ((txlength+1) > sizeof(m_i2c_buf)) return ATCA_BAD_PARAM;

//	ATCAIfaceCfg * cfg = atgetifacecfg(iface);
//
//	txlength++;         		// account for word address value byte.
//	m_i2c_buf[0] = cfg->atcai2c.slave_address;

	if (txlength > 0) {
		// From ATMEL code
		m_i2c_buf[0] = command;   	// insert the Word Address Value, Command token
		// ~From ATMEL code
		memcpy(&m_i2c_buf[1], txdata, txlength);
	} else {
		m_i2c_buf[0] = command;
	}

	/* Setup I2C parameters for number of bytes with stop - appears as follows on bus:
			   Start - address7 or address10upper - ack
			   (10 bits addressing only) address10lower - ack
			   value 1 - ack
			   value 2 - ack - stop */
//	param.num_bytes_send    = txlength + 1;
//	param.buffer_ptr_send   = m_i2c_buf;
//	param.num_bytes_rec     = 0;
//	param.stop_flag         = 1;
//	param.func_pt           = i2c_done;

	/* Set timeout (much) greater than the transfer length */
	i2c_drv_timeout(I2C1_PORT, 1000, 1000);


	/* Do master write transfer */
	m_result = -1;

	/* Function is non-blocking, returned error should be LPC_OK, but isn't checked here */
	// LPC_I2CD_API->i2c_master_transmit_intr(m_i2c_handle, &param, &result);
	sentLen = i2c_drv_write(m_i2c_handle, m_i2c_buf, txlength+1);


	/* Sleep until transfer is complete, but allow IRQ to wake system to handle I2C IRQ */
//	while (m_result == -1) {
//		__WFI();
//	}
	while (1) { // TODO: Change to use m_result
		i2c_drv_get_status_bitmap(m_i2c_handle, &txStatus);
		if (txStatus == I2C_ACTIVE){
			/* Sleep for approximate time to ensure
			 * write operation completion. Sleep value
			 * can be tuned as per requirement */
			sleep_ms(1);
		} else if (txStatus == I2C_INACTIVE) {
			break;
		} else if (txStatus == I2C_ERROR){
			while(1){
				sleep_ms(1);
			}
		}
	}

	/* Completed without errors ? */
//	if (WM_SUCCESS == m_result && sentLen == txlength + 1) {
	if (sentLen == txlength + 1) {
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
//	I2C_PARAM_T param;
//	I2C_RESULT_T result;
//	ErrorCode_t error_code = -1;
	int rcvdLen;

	int i;
	ATCA_STATUS status = ATCA_RX_NO_RESPONSE;

	if (*rxlength > sizeof(m_i2c_buf)) return ATCA_BAD_PARAM;

	ATCAIfaceCfg *cfg = atgetifacecfg(iface);

//	for (i = 0; i < cfg->rx_retries; ++i) {
		memset(m_i2c_buf, 0, *rxlength);
//		memset(&result, 0, sizeof(result));
//		m_i2c_buf[0] = cfg->atcai2c.slave_address;

		/* Setup I2C paameters for number of bytes with stop - appears as follows on bus:
				   Start - address7 or address10upper - ack
				   (10 bits addressing only) address10lower - ack
				   value 1 (read) - ack
				   value 2 read) - ack - stop */
//		param.num_bytes_send    = 0;
//		param.num_bytes_rec     = *rxlength + 1;
//		param.buffer_ptr_rec    = m_i2c_buf;
//		param.stop_flag         = 1;
//		param.func_pt           = i2c_done;

		/* Do master read transfer */
		// m_result = -1;

		/* Set timeout (much) greater than the transfer length */
		i2c_drv_timeout(I2C1_PORT, 1000, 1000);

		/* Function is non-blocking, returned error should be LPC_OK, but isn't checked here */
		rcvdLen = i2c_drv_read(m_i2c_handle, m_i2c_buf, *rxlength);

		/* Sleep until transfer is complete, but allow IRQ to wake system to handle I2C IRQ */
//		while (m_result == -1) {
//			__WFI();
//		}

		/* Completed without erors? */
//		if (WM_SUCCESS == m_result && rcvdLen > 1) {
		if (rcvdLen){
			memset(rxdata, 0, *rxlength);
			*rxlength = rcvdLen;
//			if (*rxlength > m_i2c_buf[1]) {
//				*rxlength = m_i2c_buf[1];
//			}
			memcpy(rxdata, m_i2c_buf, *rxlength);
			status = ATCA_SUCCESS;
//			break;
		} else {
			atca_delay_ms(1);
		}
//	}

	if (ATCA_SUCCESS != status) {
		*rxlength = 0;
	}

	return status;
}

/******************************************************************************/
ATCA_STATUS hal_i2c_wake(ATCAIface iface) {
//	I2C_PARAM_T param;
//	I2C_RESULT_T result;
	uint32_t txStatus;
	int sentLen;
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

//		param.num_bytes_send    = 1;
//		param.buffer_ptr_send   = m_i2c_buf;
//		param.num_bytes_rec     = 0;
//		param.stop_flag         = 1;

		/* Do master write transfer */
		// m_result = -1;

		i2c_drv_timeout(I2C1_PORT, 1000, 1000);
//		LPC_I2CD_API->i2c_master_transmit_poll(m_i2c_handle, &param, &result);
		sentLen = i2c_drv_write(m_i2c_handle, m_i2c_buf, 1);

//		atca_delay_us(700);
		sleep_ms(1); //RRR
		while (1) {
			i2c_drv_get_status_bitmap(m_i2c_handle, &txStatus);
			if (txStatus == I2C_ACTIVE){
				/* Sleep for approximate time to ensure
				 * write operation completion. Sleep value
				 * can be tuned as per requirement */
				sleep_ms(1);
			} else if (txStatus == I2C_INACTIVE) {
				break;
			} else if (txStatus == I2C_ERROR){
				while(1){
					sleep_ms(1);
				}
			}
		}

		// Receive Wake Response
		status = hal_i2c_receive(iface, response, &rxlength);
		if (status == ATCA_SUCCESS) {
			// Compare response with expected_response
			if (memcmp(response, expected_response, 4) == 0) {
//				 status = ATCA_WAKE_FAILED;
				return ATCA_SUCCESS;
			}
		}

//		if (ATCA_SUCCESS == status) {
//			return status;
//		}
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
		// Chip_I2C_DeInit(LPC_I2C);
		i2c_drv_deinit(I2C1_PORT);

		// Chip_Clock_EnablePeriphClock(SYSCTL_CLOCK_SWM);

		// Chip_SWM_DisableFixedPin(SWM_FIXED_I2C0_SDA);
		// Chip_SWM_DisableFixedPin(SWM_FIXED_I2C0_SCL);

		// Chip_Clock_DisablePeriphClock(SYSCTL_CLOCK_SWM);
	}
	return ATCA_SUCCESS;
}

#endif
