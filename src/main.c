#include <wm_os.h>
#include <app_framework.h>
#include <wmtime.h>
#include <cli.h>
#include <wmstdio.h>
#include <board.h>
#include <wmtime.h>
#include <psm-utils.h>
#include <json_parser.h>
#include <critical_error.h>
#include "appln_dbg.h"
#include "https.h"
#include "samscsdk.h"
#include "virgil/crypto.h"
#include <wmcrypto.h>
#include <wolfssl/internal.h>

extern void set_device_time();
extern void httpc_secure_post();
extern void httpc_secure_connect_post();
extern int httpc_get_cli_init();
extern int httpc_secure_get_cli_init();
extern int httpc_secure_post_cli_init();
extern int httpc_post_cli_init();
extern int httpc_post_cb_cli_init();
void sams_test();
struct wlan_network sta_net;

struct wlan_highlevel_network {
	char ssid[IEEEtypes_SSID_SIZE + 1];
	char passphrase[WLAN_PSK_MAX_LENGTH];
};

static struct wlan_highlevel_network sta_nw;
static struct wlan_highlevel_network uap_nw;
static int provisioned;
void wlan_event_wifi_initialized(void *data)
{
	/* do nothing */
}
static void event_wlan_init_done(void *data)
{
	provisioned = (int)data;
	if (strlen(sta_nw.ssid) != 0) {
		memset(&sta_net, 0, sizeof(sta_net));
		/* Set SSID as passed by the user */
		strncpy(sta_net.ssid, sta_nw.ssid, sizeof(sta_net.ssid));
		if (strlen(sta_nw.passphrase) != 0) {
			sta_net.security.type = WLAN_SECURITY_WPA2;
			/* Set the passphrase */
			strncpy(sta_net.security.psk, sta_nw.passphrase,
				sizeof(sta_net.security.psk));
			sta_net.security.psk_len = strlen(sta_net.security.psk);
		} else {
			sta_net.security.type = WLAN_SECURITY_NONE;
		}
		/* Set profile name */
		strcpy(sta_net.name, "sta-network");
		/* Set channel selection to auto (0) */
		sta_net.channel = 0;
		/* Set network type to STA */
		sta_net.type = WLAN_BSS_TYPE_STA;
		/* Set network role to STA */
		sta_net.role = WLAN_BSS_ROLE_STA;
		/* Specify address type as dynamic assignment */
		sta_net.ip.ipv4.addr_type = ADDR_TYPE_DHCP;
		app_sta_start_by_network(&sta_net);
		return;
	}
}

int common_event_handler(int event, void *data)
{
	switch (event) {
	case AF_EVT_WLAN_INIT_DONE:
	{
		if (psm_cli_init(sys_psm_get_handle(), NULL) != WM_SUCCESS)
			wmprintf("Error: psm_cli_init failed\r\n");
		event_wlan_init_done(data);
		wlan_event_wifi_initialized(data);
		break;
	}
	case AF_EVT_NORMAL_CONNECTED:
	{
		set_device_time();
		sams_test();
		break;
	}
	default:
		break;
	}
	return WM_SUCCESS;
}

/* App defined critical error */
enum app_crit_err {
	CRIT_ERR_APP = CRIT_ERR_LAST + 1,
};

/* This function is defined for handling critical error.
 * For this application, we just stall and do nothing when
 * a critical error occurs.
 */

void critical_error(int crit_errno, void *data)
{
	wmprintf("Critical Error %d: %s\r\n", crit_errno,
			critical_error_msg(crit_errno));
	while (1)
		;
	/* do nothing -- stall */
}

static void modules_init()
{
	int ret;

	ret = wmstdio_init(UART0_ID, 0);
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: wmstdio_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}

	ret = cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}
	ret = wlan_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: wlan_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}

	ret = pm_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: pm_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}
	/* Initialize time subsystem.
	 *
	 * Initializes time to 1/1/1970 epoch 0.
	 */
	ret = wmtime_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: wmtime_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}

	ret = wmtime_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: wmtime_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}

	/*ret = httpc_get_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: httpc_get_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}
	ret = httpc_secure_get_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: httpc_secure_get_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}
	ret = httpc_post_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: httpc_post_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}
	ret = httpc_post_cb_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: httpc_post_cb_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}

	ret = httpc_secure_post_cli_init();
	if (ret != WM_SUCCESS) {
		//wmprintf("Error: httpc_secure_post_cli_init failed\r\n");
		critical_error(-CRIT_ERR_APP, NULL);
	}*/
	return;
}
void sleep_ms(uint32_t delay){

	os_thread_sleep(os_msec_to_ticks(delay));
}
#define GPIO_LED_FN  PINMUX_FUNCTION_0
#include "mdev_gpio.h"
#include "mdev_pinmux.h"
void led_set_state(bool state){
	mdev_t *pinmux_dev, *gpio_dev;

	// Initialize  pinmux driver
	pinmux_drv_init();

	// Open pinmux driver
	pinmux_dev = pinmux_drv_open("MDEV_PINMUX");

	// Initialize GPIO driver
	gpio_drv_init();

        // Open GPIO driver
	gpio_dev = gpio_drv_open("MDEV_GPIO");

	int gpio_led = (board_led_1()).gpio;

	// Configure GPIO pin function for GPIO connected to LED
	pinmux_drv_setfunc(pinmux_dev, gpio_led, GPIO_LED_FN);

	// Configure GPIO pin direction as Output
	gpio_drv_setdir(gpio_dev, gpio_led, GPIO_OUTPUT);

	if (state){
		gpio_drv_write(gpio_dev, gpio_led, 0);
	}else{
		gpio_drv_write(gpio_dev, gpio_led, 1);
	}
}
int main()
{
	modules_init();

	wmprintf("Build Time: " __DATE__ " " __TIME__ "\r\n");
	memset(&sta_nw, 0, sizeof(uap_nw));
	strncpy(sta_nw.ssid, "RRR_2.4GHz", sizeof(sta_nw.ssid));
	strncpy(sta_nw.passphrase, "srv26021974", sizeof(sta_nw.passphrase));
	/* Start the application framework*/
	if (app_framework_start(common_event_handler) != WM_SUCCESS) {
		wmprintf("Failed to start application framework\r\n");
		 critical_error(-CRIT_ERR_APP, NULL);
	}
	return 0;
}
#define SAMS_IDENTITY 		"ruslan.slobozhenuk@gmail.com"
#define SAMS_IDENTITY_TYPE 	"email"
#define SAMS_USER_JSON 		"{\"username\":\"Test\"}"
#define SAMS_DATA_JSON	 	"{\"test\":\"DATA\"}"
void sams_test()
{
//	led_set_state(1);
//	sleep_ms(1000);
//	led_set_state(0);

	if(crypto_init())
	{
		wmprintf("Crypto init: " __DATE__ " " __TIME__ "\r\n");
		if(crypto_is_ready())
		{
			wmprintf("Crypto is ready: " __DATE__ " " __TIME__ "\r\n");
			uint16_t buf_size;
			char buf[HTTPS_INPUT_BUFFER_SIZE];

			buf_size = HTTPS_INPUT_BUFFER_SIZE;
			sams_verify_identity(SAMS_IDENTITY,SAMS_IDENTITY_TYPE,buf, &buf_size);
			jobj_t jobj;
			if (json_parse_start(&jobj, buf, buf_size) == WM_SUCCESS)
			{
				char validation_token[1024];
				char confirm_code[7];
				if (json_get_val_str(&jobj, "action_id", validation_token, sizeof(validation_token))== WM_SUCCESS)
				{
					int i=0;
					while (i<6)i=i+wmstdio_getchar((uint8_t *)&confirm_code[i]);confirm_code[6]='\0';

					buf_size = HTTPS_INPUT_BUFFER_SIZE;
					sams_confirm_identity(confirm_code,validation_token,3600,10,buf, &buf_size);
					if (json_parse_start(&jobj, buf, buf_size) == WM_SUCCESS)
					{

						if (json_get_val_str(&jobj, "validation_token", validation_token, sizeof(validation_token))== WM_SUCCESS)
						{
							/*char 		answer[2048];
					uint16_t 	answer_len=2048;
					sams_validate_identity(SAMS_IDENTITY,SAMS_IDENTITY_TYPE,validation_token);
					uint8_t private_key[128];
					uint8_t public_key[128];
					size_t private_key_sz=0;
					size_t  public_key_sz=0;

					//RsaKey genKey;
					//RNG    rng;
					//int    ret;

					//DH_PG_PARAMS params;
					//params.generator = &GEN;
					//params.generatorLen = 1;
					//params.prime = DH_PRIME_1536;
					//params.primeLen = sizeof(DH_PRIME_1536);

					//pwps_info->dh =  mrvl_dh_setup_key(pwps_info->registrar.public_key, SZ_PUBLIC_KEY, pwps_info->registrar.private_key,SZ_PRIVATE_KEY, &params);
					InitRng(&rng);
					InitRsaKey(&genKey, 0);

					ret = MakeRsaKey(&genKey, 1024, 65537, &rng);
					if (ret != 0)*/
							//crypto_create_key_pair(private_key, 128,&private_key_sz,public_key, 128,&public_key_sz);
							//sams_new_user (SAMS_IDENTITY,SAMS_IDENTITY_TYPE,validation_token,public_key,public_key_sz,private_key,private_key_sz,"",0,SAMS_USER_JSON,SAMS_DATA_JSON,answer,&answer_len);
							volatile int tmp=0;
							tmp=1;
						}
					}
				}
			}
		}
		else
		{
			wmprintf("Error!!! Crypto is not ready!!!: " __DATE__ " " __TIME__ "\r\n");
		}
	}
	else
	{
		wmprintf("Error!!! Crypto is not init!!!: " __DATE__ " " __TIME__ "\r\n");
	}
}
