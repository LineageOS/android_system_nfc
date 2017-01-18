/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#ifndef BT_TARGET_H
#define BT_TARGET_H

#include "data_types.h"

#ifdef BUILDCFG
#include "buildcfg.h"
#endif

/* Include common GKI definitions used by this platform */
#include "gki_target.h"

#include "bt_types.h"   /* This must be defined AFTER buildcfg.h */

#define BTAPI

#define BT_API          BTAPI

#ifdef __cplusplus
extern "C" {
#endif
BT_API extern void bte_ncisu_send (NFC_HDR *p_pkt, uint16_t event);
BT_API extern void bte_hcisu_send (NFC_HDR *p_msg, uint16_t event);
#if (HCISU_H4_INCLUDED == TRUE)
BT_API extern void bte_hcisu_lp_allow_bt_device_sleep (void);
BT_API extern void bte_hcisu_lp_wakeup_host (void);
BT_API extern void bte_hcisu_lp_h4ibss_evt(uint8_t *p, uint8_t evt_len);
#endif

/* HCILL API for the applications */
typedef void (tHCILL_SLEEP_ACK)(void);
BT_API extern void HCILL_GoToSleep( tHCILL_SLEEP_ACK *sl_ack_fn);
typedef void (tHCILL_STATE_CBACK)(bool    is_sleep);
BT_API extern void HCILL_RegState( tHCILL_STATE_CBACK *p_cback);
#ifdef __cplusplus
}
#endif

/* Sends ACL data received from the upper stack to the BD/EDR HCI transport. */
#ifndef HCI_ACL_DATA_TO_LOWER
#define HCI_ACL_DATA_TO_LOWER(p)    bte_hcisu_send((NFC_HDR *)(p), BT_EVT_TO_LM_HCI_ACL);
#endif

#ifndef HCI_BLE_ACL_DATA_TO_LOWER
#define HCI_BLE_ACL_DATA_TO_LOWER(p)    bte_hcisu_send((NFC_HDR *)(p), (uint16_t)(BT_EVT_TO_LM_HCI_ACL|LOCAL_BLE_CONTROLLER_ID));
#endif

/* Sends ACL data received from the upper stack to the AMP HCI transport. */
#ifndef HCI_AMP_DATA_TO_LOWER
#define HCI_AMP_DATA_TO_LOWER(p,x)    bte_hcisu_send((NFC_HDR *)(p), (uint16_t)(BT_EVT_TO_LM_HCI_ACL|((uint16_t)(x))));
#endif

/* Sends SCO data received from the upper stack to the HCI transport. */
#ifndef HCI_SCO_DATA_TO_LOWER
#define HCI_SCO_DATA_TO_LOWER(p)    bte_hcisu_send((NFC_HDR *)(p), BT_EVT_TO_LM_HCI_SCO);
#endif

/* Sends an HCI command received from the upper stack to the BD/EDR HCI transport. */
#ifndef HCI_CMD_TO_LOWER
#define HCI_CMD_TO_LOWER(p)         bte_hcisu_send((NFC_HDR *)(p), BT_EVT_TO_LM_HCI_CMD);
#endif

/* Sends an HCI command received from the upper stack to the AMP HCI transport. */
#ifndef HCI_CMD_TO_AMP
#define HCI_CMD_TO_AMP(x,p)         bte_hcisu_send((NFC_HDR *)(p), (uint16_t)(BT_EVT_TO_LM_HCI_CMD|((uint16_t)(x))));
#endif

/* Sends an LM Diagnosic command received from the upper stack to the HCI transport. */
#ifndef HCI_LM_DIAG_TO_LOWER
#define HCI_LM_DIAG_TO_LOWER(p)     bte_hcisu_send((NFC_HDR *)(p), BT_EVT_TO_LM_DIAG);
#endif

/* Send HCISU a message to allow BT sleep */
#ifndef HCI_LP_ALLOW_BT_DEVICE_SLEEP
#if (HCISU_H4_INCLUDED == TRUE)
#define HCI_LP_ALLOW_BT_DEVICE_SLEEP()       bte_hcisu_lp_allow_bt_device_sleep()
#else
#define HCI_LP_ALLOW_BT_DEVICE_SLEEP()       HCILP_AllowBTDeviceSleep()
#endif
#endif

/* Send HCISU a message to wakeup host */
#ifndef HCI_LP_WAKEUP_HOST
#if (HCISU_H4_INCLUDED == TRUE)
#define HCI_LP_WAKEUP_HOST()        bte_hcisu_lp_wakeup_host()
#else
#define HCI_LP_WAKEUP_HOST()        HCILP_WakeupHost()
#endif
#endif

/* Send HCISU the received H4IBSS event from controller */
#ifndef HCI_LP_RCV_H4IBSS_EVT
#if (HCISU_H4_INCLUDED == TRUE)
#define HCI_LP_RCV_H4IBSS_EVT(p1, p2)  bte_hcisu_lp_h4ibss_evt((uint8_t*)(p1), (uint8_t)(p2))
#else
#define HCI_LP_RCV_H4IBSS_EVT(p1, p2)  h4ibss_sleep_mode_evt((uint8_t*)(p1), (uint8_t)(p2))
#endif
#endif

/* Quick Timer */
/* minimum should have 100 millisecond resolution for eL2CAP */
/* if HCILP_INCLUDED is TRUE     then it should have 100 millisecond resolution */
/* if SLIP_INCLUDED is TRUE      then it should have 10 millisecond resolution  */
/* if BRCM_USE_DELAY is FALSE then it should have 10 millisecond resolution  */
/* if none of them is included then QUICK_TIMER_TICKS_PER_SEC is set to 0 to exclude quick timer */
#ifndef QUICK_TIMER_TICKS_PER_SEC
#define QUICK_TIMER_TICKS_PER_SEC   100       /* 10ms timer */
#endif

#include "bt_trace.h"

#endif /* BT_TARGET_H */

