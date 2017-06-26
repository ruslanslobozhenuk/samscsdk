/*
 * https.h
 *
 *  Created on: 16 θών. 2017 γ.
 *      Author: Ruslan
 */

#ifndef INCLUDE_HTTPS_H_
#define INCLUDE_HTTPS_H_
#include <stdint.h>

#define HTTPS_INPUT_BUFFER_SIZE 1024

#define HTTPS_RET_CODE_ERROR_OPEN_SESSION	1000
#define HTTPS_RET_CODE_ERROR_PREPARE_REQ	1001
#define HTTPS_RET_CODE_ERROR_SEND_REQ		1002
#define HTTPS_RET_CODE_ERROR_GET			1003
#define HTTPS_RET_CODE_OK 200

uint16_t https_post(const char* url, const char* data, uint16_t in_size, char* out_data, uint16_t* in_out_size);
uint16_t https_get(const char* url, char* out_data, uint16_t* in_out_size);
#endif /* INCLUDE_HTTPS_H_ */
