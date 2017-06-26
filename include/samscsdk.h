/*
 * samscsdk.h
 *
 *  Created on: 14 θών. 2017 γ.
 *      Author: Ruslan
 */

#ifndef INCLUDE_SAMSCSDK_H_
#define INCLUDE_SAMSCSDK_H_
#include <stdint.h>
#include <stdbool.h>

#define SAMS_OK			0
#define SAMS_FAIL		-1

int16_t sams_verify_identity (const char *in_identity, const char *in_identity_type,char *out_panswer,uint16_t *in_out_panswer_len);
int16_t sams_confirm_identity (const char *confirmation_code, const char* action_id, const uint32_t time_to_live, const uint32_t count_to_live, char* out_answer, uint16_t* in_out_answer_len);
int16_t	sams_validate_identity (const char *identity, const char *identity_type, const char *validation_token);

//Users operations
int16_t sams_new_user (const char *identity,const char *identityType,const char *validation_token,const uint8_t *pub_key,const uint16_t pub_key_len,const uint8_t *priv_der_key,const uint16_t priv_der_key_len,const uint8_t *priv_der_key_password,const uint16_t priv_der_key_password_len,const char *user_data_json,const char *data_json,char *out_panswer, uint16_t *in_out_panswer_len);
int16_t sams_get_user(const char* _id_user, char* _out_panswer, uint32_t* __in_out_panswer_len);
int16_t sams_put_user(const char* _pidentity, const char* _pidentityType, const char* _pvalidation_token, const uint8_t* _pub_key, const uint32_t _pub_key_len, const uint8_t* _priv_der_key, const uint32_t _priv_der_key_len, const uint8_t* _priv_der_key_password, const uint32_t _priv_der_key_password_len, const char* _user_data_json, const char* _data_json, char* _out_panswer, uint32_t* __in_out_panswer_len);
//Account operations
int16_t sams_new_account(const char * _id_user, const char * _id_autentification_card,const uint8_t * _autentification_card_private_key, const uint32_t  _autentification_card_private_key_len,const uint8_t* _priv_key_password, const uint32_t _priv_key_password_len,const char * _user, const char * _description, const char * _data,char* _out_panswer, uint32_t* __in_out_panswer_len);
int16_t sams_get_account(const char * _account_id, const char * _id_autentification_card,const uint8_t * _autentification_card_private_key, const uint32_t  _autentification_card_private_key_len,const uint8_t* _priv_key_password, const uint32_t _priv_key_password_len, char* _out_panswer, uint32_t* __in_out_panswer_len);
int16_t sams_del_account(const char * _id_user, const char * _account_id, const char * _id_autentification_card, const uint8_t * _autentification_card_private_key, const uint32_t  _autentification_card_private_key_len, const uint8_t* _priv_key_password, const uint32_t _priv_key_password_len, char* _out_panswer, uint32_t* __in_out_panswer_len);
int16_t sams_put_account(const char * _id_user, const char * _id_autentification_card,const uint8_t * _autentification_card_private_key, const uint32_t  _autentification_card_private_key_len,const uint8_t* _priv_key_password, const uint32_t _priv_key_password_len,const char * _user, const char * _description, const char * _data, char* _out_panswer, uint32_t* __in_out_panswer_len);

#endif /* INCLUDE_SAMSCSDK_H_ */
