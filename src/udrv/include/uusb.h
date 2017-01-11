/******************************************************************************
 *
 *  Copyright (C) 2001-2012 Broadcom Corporation
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

/******************************************************************************
 *
 *  This file contains usb definitions from Widcomm's Universal Embedded
 *  Drivers API.
 *
 ******************************************************************************/

#ifndef UUSB_H
#define UUSB_H

#include "bt_target.h"
#ifdef __cplusplus
extern "C" {
#endif


/*******************************************************************************
** Codec APIs
*******************************************************************************/


/**** Status ****/
#define UUSB_SUCCESS                                  0
#define UUSB_DRV_INVALID_PARM                         1   // Invalid parameter(s) passed to Driver
#define UUSB_DRV_INVALID_STATE                        2   // Driver is not in correct state to accept
#define UUSB_DRV_UNSUPPORTED_SETUP_REQ                3   // Unsupported SETUP request (use with tUSER_EP0_SETUP_CB)
#define UUSB_DRV_NO_BUFFER_AVAILABLE                  4   // User cannot provide a Buffer (use with CB functions)

typedef uint8_t tUUSB_STATUS;


#define  UUSB_EP1   0
#define  UUSB_EP2   1
#define  UUSB_EP3   2
#define  UUSB_EP4   3
#define  UUSB_EP5   4
#define  UUSB_EP6   5
#define  UUSB_EP7   6

typedef uint8_t tUUSB_EP_ID;

typedef enum {
  UUSB_EP_TYPE_CONTROL = 0,
  UUSB_EP_TYPE_ISOCHRONOUS,
  UUSB_EP_TYPE_BULK,
  UUSB_EP_TYPE_INTERRUPT
} tUUSB_EP_TYPE;

typedef enum {
  UUSB_DIR_OUT = 0,
  UUSB_DIR_IN
} tUUSB_EP_DIRECTION;

typedef struct tUUSB_SETUP_PKTTag
{
/* Definition of "USBbmRequestType" */
#define UUSB_DATA_PHASE_DIR      0x80    /* Mask to get data phase transfer direction */
#define UUSB_HOST_TO_DEVICE      0x00    /* Data transfer directions */
#define UUSB_DEVICE_TO_HOST      0x80    /* Data transfer directions */
/* Types of requests */
#define UUSB_REQUEST_TYPE		0x60	/* Mask to get request type */
#define UUSB_STANDARD_REQUEST	0x00	/* Standard request */
#define	UUSB_CLASS_REQUEST		0x20	/* Class request */
#define	UUSB_VENDOR_REQUEST		0x40	/* Vendor request */
  uint8_t bmRequestType;
  uint8_t bRequest;
  uint16_t wValue;
  uint16_t wIndex;
  uint16_t wLength;
} tUUSB_SETUP_PKT;

typedef union
{
#define UUSB_HEAD_SIZE (8)
	uint8_t         HeadBytes[UUSB_HEAD_SIZE];
    tUUSB_SETUP_PKT Setup;
} tSETUP_OR_HEAD;

typedef struct
{
  uint8_t      BufSize;
  uint8_t      NumBytesInBuf;
  tSETUP_OR_HEAD Buf;
} tUUSB_RX_HEAD;

typedef enum
{
  UUSB_EP_DISABLE,
  UUSB_EP_ENABLE,
  UUSB_EP_STALL
} tUUSB_EP_STATE;

typedef uint8_t tEndPoint;

#if 0
#define  UUSB_ATTACHED      0
#define  UUSB_POWERED       1
#define  UUSB_DEFAULT       2
#define  UUSB_ADDRESS       3
#define  UUSB_CONFIGURED    4
#define  UUSB_SUSPENDED     5

typedef uint8_t tUUSB_BUS_STATE;
#else
typedef enum
{
  UUSB_ATTACHED,
  UUSB_POWERED,
  UUSB_DEFAULT,
  UUSB_ADDRESS,
  UUSB_CONFIGURED,
  UUSB_SUSPENDED
} tUUSB_BUS_STATE;
#endif

typedef enum _tUUSB_STANDART_REQ
{
	UUSB_GET_STATUS = 0,
	UUSB_CLEAR_FEATURE,
	UUSB_RESERVED1,
	UUSB_SET_FEATURE,
	UUSB_RESERVED2,
	UUSB_SET_ADDRESS,
	UUSB_GET_DESCRIPTOR,
	UUSB_SET_DESCRIPTOR,
	UUSB_GET_CONFIGURATION,
	UUSB_SET_CONFIGURATION,
	UUSB_GET_INTERFACE,
	UUSB_SET_INTERFACE,
	UUSB_TOTAL_sREQUEST,				/* Total number of Standard request */
	UUSB_SYNCH_FRAME = 12
} tUUSB_STANDART_REQ;


typedef void (*tUUSB_STATE_CB)          (tUUSB_BUS_STATE State);
typedef void (*tUUSB_PROT_COMPLETE_CB ) (uint8_t *pBuf,uint16_t NumBytesInBuf);

typedef tUUSB_STATUS (*tUUSB_PROT_SETUP_CB ) (uint8_t **ppBuf,uint16_t *pBufSize);

typedef void (*tUUSB_RX_START_CB )      (tUUSB_EP_ID EndPoint,
                                        uint8_t **ppBuf,
                                        uint16_t *pBufSize);

typedef void (*tUUSB_RX_COMPLETE_CB )   (tUUSB_EP_ID EndPoint,
                                        uint8_t *pRxBuf,
                                        uint16_t NumBytesInBuf);

typedef void (*tUUSB_TX_COMPLETE_CB )   (tUUSB_EP_ID EndPoint,
                                        uint8_t *pRxBuf);
/*******************************************************************************
** Function Prototypes
*******************************************************************************/

/******************************************************************************
**
** Function         UCODEC_Init
**
** Description      Startup initialisation function. This function is called
**                  before any orther function of UUSB it initialize UUSB
**                  internal structure an the external hw.
**
**                  Input :
**
**                  Output Parameters :
**
** Returns          UUSB_SUCCESS if The action was performed with sucess.
**                  Error code else.
**
******************************************************************************/
BT_API extern tUUSB_STATUS    UUSB_Init    (tUUSB_PROT_SETUP_CB       userProtSetupCallBack,
                                            tUUSB_PROT_COMPLETE_CB    userProtCompleteCallBack,
                                            tUUSB_RX_START_CB         userRxStartCallBack,
                                            tUUSB_STATE_CB            userStateCallBack,
                                            tUUSB_TX_COMPLETE_CB      userTxCompleteCallBack,
                                            tUUSB_RX_COMPLETE_CB      userRxCompleteCallBack);




/******************************************************************************
**
** Function         UUSB_Start
**
** Description
**
**
**
**
**
** Returns          UUSB_SUCCESS if The action was performed with sucess.
**
******************************************************************************/
BT_API extern tUUSB_STATUS    UUSB_Start  (void);

/******************************************************************************
**
** Function         UUSB_Stop
**
** Description
**
**
**
**
** Returns          UUSB_SUCCESS if The action was performed with sucess.
**                  Error code else.
**
******************************************************************************/
BT_API extern tUUSB_STATUS    UUSB_Stop      (void);

/******************************************************************************
**
** Function         UUSB_SetEndPointCnf
**
** Description
**
**
** Returns
**
******************************************************************************/
BT_API extern tUUSB_STATUS    UUSB_SetEndPointCnf ( bool            IsIN_EndPoint,
                                                    tUUSB_EP_ID     EndPoint,
                                                    uint8_t         MaxPacketSize,
                                                    tUUSB_EP_TYPE   EndPointType,
                                                    tUUSB_RX_HEAD   *pRxHead,
                                                    uint16_t        RxTimeOut);


/******************************************************************************
**
** Function         UUSB_SetEndPointState
**
** Description
**
**
** Returns
**
******************************************************************************/
BT_API extern tUUSB_STATUS UUSB_SetEndPointState (tUUSB_EP_ID    EndPoint,
                                                    tUUSB_EP_STATE EndPointState);

/******************************************************************************
**
** Function         UUSB_WriteEndPoint
**
** Description
**
**
** Returns
**
******************************************************************************/
BT_API extern tUUSB_STATUS UUSB_WriteEndPoint (tUUSB_EP_ID     EndPoint,
                                                uint16_t   Length,
                                                uint8_t*    pBuf);

/******************************************************************************
**
** Function         UUSB_GenerateRemoteWakeUp
**
** Description
**
**
** Returns
**
******************************************************************************/
BT_API extern tUUSB_STATUS UUSB_GenerateRemoteWakeUp (void);

#ifdef __cplusplus
};
#endif


#endif /* UUSB_H */
