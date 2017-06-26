/*
 * https.c
 *
 *  Created on: 16 θών. 2017 γ.
 *      Author: Ruslan
 */
#include <httpc.h>
#include "appln_dbg.h"
#include "../include/https.h"
http_session_t handle;

uint16_t https_post(const char* url, const char* data, uint16_t in_size, char* out_data, uint16_t* in_out_size)
{
	dbg("POST:[%s] DATA[%s]", url,data);

	int rv = http_open_session(&handle, (char*)url, NULL);
	if (rv != 0) {
		dbg("Open session failed: %s (%d)", url, rv);
		return HTTPS_RET_CODE_ERROR_OPEN_SESSION;
	}
	http_req_t req = {
		.type = HTTP_POST,
		.resource = (char*)url,
		.version = HTTP_VER_1_1,
		.content = (char*)data,
		.content_len = in_size,
	};

	rv = http_prepare_req(handle, &req,
				  STANDARD_HDR_FLAGS |
				  HDR_ADD_CONN_KEEP_ALIVE);
	if (rv != 0) {
		dbg("Prepare request failed: %d", rv);
		return HTTPS_RET_CODE_ERROR_PREPARE_REQ;
	}

	rv = http_send_request(handle, &req);
	if (rv != 0) {
		dbg("Send request failed: %d", rv);
		return HTTPS_RET_CODE_ERROR_SEND_REQ;
	}
	static http_resp_t *resp;
	rv = http_get_response_hdr(handle, &resp);
	dbg("POST:[%s] TASK(%x): STATUS:<%d>\r\n", url,os_get_current_task_handle(),resp->status_code);
	uint16_t read_bytes;
	uint16_t offset=0;
	while((read_bytes=http_read_content(handle,out_data+offset,*in_out_size-offset))>0)
		offset+=read_bytes;
	out_data[offset]='\0';
	*in_out_size=offset;
	dbg("DATA:[%s]\r\n", out_data);
	http_close_session(&handle);
	return resp->status_code;
}

uint16_t https_get(const char* url, char* out_data, uint16_t* in_out_size)
{
	dbg("GET:[%s]", url);
	http_resp_t 	*resp;
	int rv = httpc_get(url, &handle, &resp, NULL);
	if (rv != WM_SUCCESS) {
		dbg("%s httpc_get: failed\r\n", url);
		return HTTPS_RET_CODE_ERROR_GET;
	}
	dbg("GET:[%s] TASK(%x): STATUS:<%d>\r\n", url,os_get_current_task_handle(),resp->status_code);
	*in_out_size = http_read_content(handle,out_data,*in_out_size);
	out_data[*in_out_size]='\0';
	dbg("DATA:[%s]\r\n", out_data);
	http_close_session(&handle);
	return resp->status_code;
}
