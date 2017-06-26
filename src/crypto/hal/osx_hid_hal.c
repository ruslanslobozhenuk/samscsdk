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
 * @file osx_hal_hid.c
 * @brief Hardware abstraction layer for osx hid (ATECC508A used for now).
 *
 ******************************************************************************/

#if defined(ATCA_HAL_KIT_HID)

#include <../HID_Utilities/HID_Utilities_External.h>

#include <hal/atca_hal.h>
#include <hal/kit_phy.h>

#include <unistd.h>
#include <IOKit/hid/IOHIDLib.h>


#if !defined (VIRGIL_HAL_DEBUG)
//#define VIRGIL_HAL_DEBUG
#endif

static IOHIDDeviceRef hid_crypto_device = 0;

#define RX_BUF_SZ 1024
static uint8_t rx_buf[RX_BUF_SZ];
static size_t rx_buf_fill = 0;

/******************************************************************************/
void atca_delay_us(uint32_t delay) {
    usleep(delay);
}

/******************************************************************************/
void atca_delay_10us(uint32_t delay) {
    useconds_t val;
    val = 10;
    val *= delay;
    usleep(val);
}

/******************************************************************************/
void atca_delay_ms(uint32_t delay) {
    useconds_t val;
    val = 1000 * 5;
    val *= delay;
    usleep(val);
}

/******************************************************************************/
static void hid_enumerate_callback(void *inContext, IOReturn inResult, void *inSender, IOHIDDeviceRef inIOHIDDeviceRef) {
#if 0
    HIDDumpDeviceInfo(inIOHIDDeviceRef);
#endif
    const uint32_t vendor_id = IOHIDDevice_GetVendorID(inIOHIDDeviceRef);
    const uint32_t product_id = IOHIDDevice_GetProductID(inIOHIDDeviceRef);
#if defined (VIRGIL_HAL_DEBUG)
    printf("HID device found: vid : 0x%x   pid : 0x%x\n",
           (unsigned long)vendor_id,
           (unsigned long)product_id);
#endif
    hid_crypto_device = inIOHIDDeviceRef;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_init(void *hal, ATCAIfaceCfg *cfg) {
    hid_crypto_device = 0;
    
    if (0 == cfg) {
        return ATCA_FUNC_FAIL;
    }
    
    // create the manager
    gIOHIDManagerRef = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
    if (!gIOHIDManagerRef) {
        printf("ERROR: Can't create HID Manager.\n");
        return ATCA_FUNC_FAIL;
    }
    
    // register our matching & removal callbacks
    IOHIDManagerRegisterDeviceMatchingCallback(gIOHIDManagerRef, hid_enumerate_callback, 0);

    // schedule us with the run loop
    IOHIDManagerScheduleWithRunLoop(gIOHIDManagerRef, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    // Create a Matching Dictionary
    CFMutableDictionaryRef match_dict = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                  2,
                                                                  &kCFTypeDictionaryKeyCallBacks,
                                                                  &kCFTypeDictionaryValueCallBacks);
    
    // Specify a device manufacturer in the Matching Dictionary
    SInt32 vendor_id = cfg->atcahid.vid;
    SInt32 product_id = cfg->atcahid.pid;
    CFDictionarySetValue(match_dict,
                         CFSTR(kIOHIDVendorIDKey),
                         CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, &vendor_id));
    CFDictionarySetValue(match_dict,
                         CFSTR(kIOHIDProductIDKey),
                         CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, &product_id));
    
    // Register the Matching Dictionary to the HID Manager
    IOHIDManagerSetDeviceMatching(gIOHIDManagerRef, match_dict);
    
    // open it
    if (kIOReturnSuccess != IOHIDManagerOpen(gIOHIDManagerRef, kIOHIDOptionsTypeNone)) {
        printf("ERROR: Can't open HID manager\n");
        return ATCA_FUNC_FAIL;
    }
#if defined (VIRGIL_HAL_DEBUG)
    printf("SUCCESS: HID Manager opened\n");
#endif
    
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 3, false);
    
    IOHIDManagerClose(gIOHIDManagerRef, 0);
    CFRelease(match_dict);
    
    if (!hid_crypto_device) {
        printf("ERROR: Crypto device not found.\n");
        return ATCA_NO_DEVICES;
    }
    
    // Open found device
    if (kIOReturnSuccess != IOHIDDeviceOpen(hid_crypto_device, kIOHIDOptionsTypeNone)) {
        printf("ERROR: Can't open device.");
        return ATCA_NO_DEVICES;
    }
    
    return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_post_init(ATCAIface iface) {
    ATCAIfaceCfg * cfg = atgetifacecfg(iface);
    
    // Check the pointers
    if (!cfg) {
        printf("ERROR: hal_kit_hid_post_init bad params");
        return ATCA_BAD_PARAM;
    }
    
    // Perform the kit protocol init
    if (ATCA_SUCCESS != kit_init(iface)) {
        printf("ERROR: kit_init() Failed");
        return ATCA_GEN_FAIL;
    }
    
    return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_send(ATCAIface iface, uint8_t *txdata, int txlength) {
    return kit_send(iface, txdata, txlength);
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength) {
    return kit_receive(iface, rxdata, rxlength);
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_wake(ATCAIface iface) {
    return kit_wake(iface);
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_idle(ATCAIface iface) {
    return kit_idle(iface);
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_sleep(ATCAIface iface) {
    return kit_sleep(iface);
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_release(void *hal_data) {
    if (hid_crypto_device) {
        IOHIDDeviceClose(hid_crypto_device, 0);
    }
    return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_discover_buses(int i2c_buses[], int max_buses) {
    return ATCA_UNIMPLEMENTED;
}

/******************************************************************************/
ATCA_STATUS hal_kit_hid_discover_devices(int busNum, ATCAIfaceCfg *cfg, int *found) {
    return ATCA_UNIMPLEMENTED;
}

/******************************************************************************/
ATCA_STATUS kit_phy_num_found(int8_t * num_found) {
    num_found = hid_crypto_device ? 1 : 0;
    return ATCA_SUCCESS;
}

/******************************************************************************/
ATCA_STATUS kit_phy_send(ATCAIface iface, uint8_t *txdata, int txlength) {
    if (!hid_crypto_device) {
        return ATCA_RX_FAIL;
    }
    
    if (kIOReturnSuccess != IOHIDDeviceSetReport(hid_crypto_device,
                                                 kIOHIDReportTypeOutput,
                                                 0,
                                                 txdata,
                                                 txlength)) {
        return ATCA_RX_FAIL;
    }
    return ATCA_SUCCESS;
}

/******************************************************************************/
static void receive_callback(void * context,
                             IOReturn result,
                             void * deviceRef,
                             IOHIDReportType type,
                             uint32_t reportID,
                             uint8_t * report,
                             CFIndex length) {
    if(!result && report && deviceRef) {
        if (!rx_buf_fill) {
            strcpy((char *)rx_buf, (const char *)report);
        } else {
            strcat((char *)rx_buf, (const char *)report);
        }
        rx_buf_fill += strlen((char *)report);
    } else {
        rx_buf_fill = 0;
    }
    
    CFRunLoopStop(CFRunLoopGetCurrent());
}

/******************************************************************************/
ATCA_STATUS kit_phy_receive(ATCAIface iface, uint8_t* rxdata, int* rxlength) {
    uint8_t tmp_buf[RX_BUF_SZ];
    rx_buf_fill = 0;
    
    if (!hid_crypto_device) {
        return ATCA_RX_FAIL;
    }
    
    // Register a callback
    IOHIDDeviceRegisterInputReportCallback(hid_crypto_device, tmp_buf, RX_BUF_SZ, receive_callback, 0);
    
    // Schedule the device on the current run loop in case it isn't already scheduled
    IOHIDDeviceScheduleWithRunLoop(hid_crypto_device, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    // Trap in the run loop until a report is received
    bool res = kCFRunLoopRunTimedOut != CFRunLoopRunInMode(kCFRunLoopDefaultMode, 5, false);
    
    // The run loop has returned, so unschedule the device
    IOHIDDeviceUnscheduleFromRunLoop(hid_crypto_device, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    if (res && rx_buf_fill && rx_buf_fill <= *rxlength) {
        *rxlength = rx_buf_fill;
        memcpy(rxdata, rx_buf, rx_buf_fill);
    } else {
        *rxlength = 0;
        res = false;
    }
    
    return res ? ATCA_SUCCESS : ATCA_RX_FAIL;
}

#endif
