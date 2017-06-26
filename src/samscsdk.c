/*
 * samscsdk.c
 *
 *  Created on: 14 θών. 2017 γ.
 *      Author: Ruslan
 */

#include "../include/samscsdk.h"
#include "../include/https.h"

#include <json_generator.h>
#include <json_parser.h>

#define SHA256_DIGEST_SIZE (32)

int16_t sams_verify_identity(const char* in_identity, const char* in_identity_type,char* out_answer,uint16_t* in_out_answer_len){
	int16_t ret=SAMS_OK;
	char json_buffer[512];
	struct json_str json;
	json_str_init(&json, json_buffer,512);
	json_start_object(&json);
	json_set_val_str(&json, "type", in_identity_type);
	json_set_val_str(&json, "value", in_identity);
	json_set_val_str(&json, "scope", "global");
	json_close_object(&json);
	if((ret=https_post("https://identity-stg.virgilsecurity.com/v1/verify", json.buff, json.free_ptr, out_answer, in_out_answer_len))!=HTTPS_RET_CODE_OK)
		ret=ret*(-1);
	return SAMS_OK;
}

int16_t sams_confirm_identity(const char* confirmation_code, const char* action_id, const uint32_t time_to_live, const uint32_t count_to_live, char* out_answer, uint16_t* in_out_answer_len)
{
	int16_t ret=SAMS_OK;
	char json_buffer[512];
	struct json_str json;
	json_str_init(&json, json_buffer, 512);
	json_start_object(&json);
	json_set_val_str(&json, "confirmation_code", confirmation_code);
	json_set_val_str(&json, "action_id", action_id);
	json_push_object(&json, "token");
	json_set_val_int(&json, "time_to_live", time_to_live);
	json_set_val_int(&json, "count_to_live", count_to_live);
	json_pop_object(&json);
	json_close_object(&json);
	if((ret=https_post("https://identity-stg.virgilsecurity.com/v1/confirm", json.buff, json.free_ptr, out_answer, in_out_answer_len))!=HTTPS_RET_CODE_OK)
		ret=ret*(-1);
	return ret;
}

int16_t sams_validate_identity (const char *identity, const char *identity_type, const char *validation_token)
{
	int16_t ret=SAMS_OK;
	char json_buffer[2048];
	struct json_str json;
	json_str_init(&json, json_buffer, 2048);
	json_start_object(&json);
	json_set_val_str(&json, "type", identity_type);
	json_set_val_str(&json, "value", identity);
	json_set_val_str(&json, "validation_token", validation_token);
	json_close_object(&json);
	uint16_t answer_len=2048;
	if((ret=https_post("https://identity-stg.virgilsecurity.com/v1/validate", json.buff, json.free_ptr, json_buffer, &answer_len))!=HTTPS_RET_CODE_OK)
		ret=ret*(-1);
	return ret;
}

int16_t sams_new_user (const char *identity,const char *identityType,const char *validation_token,const uint8_t *pub_key,const uint16_t pub_key_len,const uint8_t *priv_der_key,const uint16_t priv_der_key_len,const uint8_t *priv_der_key_password,const uint16_t priv_der_key_password_len,const char *user_data_json,const char *data_json,char *out_panswer, uint16_t *in_out_panswer_len){

/*	int buf_len = 2048;
	char json_buffer[512];
	char tmp_buffer[2048];
	struct json_str json;
	json_str_init(&json, json_buffer, 512);
	json_start_object(&json);
	json_set_val_str(&json, "identity", identity);
	json_set_val_str(&json, "identity_type", identityType);
	base64encode(pub_key, pub_key_len, tmp_buffer, &buf_len);
	json_set_val_str(&json, "public_key", tmp_buffer);
	json_set_val_str(&json, "scope", "global");
	json_push_object(&json, "data");
	//json_set_object_value(&json, "", user_data_json, 0, 0, 0, JSON_VAL_RAW);
	json_close_object(&json);
	json_close_object(&json);

	uint8_t digest[SHA256_DIGEST_SIZE];
//	sw_sha256(json.buff, json.free_ptr, digest);
	uint32_t signature_len = 512;
	uint8_t signature[512];
//	if (virgil_get_signature(digest, SHA256_DIGEST_SIZE, priv_der_key, priv_der_key_len, priv_der_key_password, priv_der_key_password_len, signature, &signature_len))
	{
		char json_request_buffer[4096];
		struct json_str request_json;
		json_str_init(&request_json, json_request_buffer, 4096);
		json_start_object(&request_json);
		buf_len = 2048;
		base64encode(json.buff, json.free_ptr, tmp_buffer, &buf_len);
		json_set_val_str(&request_json, "content_snapshot", tmp_buffer);
		json_push_object(&request_json, "meta");
		json_push_object(&request_json, "signs");
		base64encode(signature, signature_len, tmp_buffer, &buf_len);
		buf_len = 512;
//		data_to_hex(digest, SHA256_DIGEST_SIZE, json_buffer, &buf_len);
		json_set_val_str(&request_json, json_buffer, tmp_buffer);
		json_close_object(&request_json);
		json_push_object(&request_json, "validation");
		json_set_val_str(&request_json, "token", validation_token);
		json_close_object(&request_json);
		json_close_object(&request_json);
		json_close_object(&request_json);

		buf_len = 2048;
		char json_post_buffer[4096];
		struct json_str post_json;
		json_str_init(&post_json, json_post_buffer, 4096);
		json_start_object(&post_json);
		json_push_object(&post_json, "meta");
		json_push_object(&post_json, "virgil_card");
		base64encode(request_json.buff, request_json.free_ptr, tmp_buffer, &buf_len);
		json_set_val_str(&post_json, "request_content", tmp_buffer);
		json_close_object(&post_json);
		json_close_object(&post_json);
		json_close_object(&post_json);
//		return post("https://soraa-accman-stg.virgilsecurity.com/v1/user", NULL, post_json.buff, post_json.free_ptr, out_panswer,in_out_panswer_len);
	}
//	else
//		return CALCULATE_SIGNATURE_FAIL;*/
	return 0;
}
