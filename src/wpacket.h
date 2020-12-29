/*
** Copyright (c) , 2004, Seunghyun Seo 
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without 
** modification, are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright notice, 
**    this list of conditions and the following disclaimer. 
**
** 2. Redistributions in binary form must reproduce the above copyright notice, 
**    this list of conditions and the following disclaimer in the documentation 
**    and/or other materials provided with the distribution. 
**
** 3. Neither the name of the Panicsecurity Co., LTD. nor the names of its 
**    contributors may be used to endorse or promote products derived from 
**    this software without specific prior written permission. 
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
** DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE 
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* $Id: wpacket.h,v 1.2 2004/06/24 11:48:41 seunghyun Exp $ */

/* 
 * wpacket.h 
 *
 * last update :
 *  2003/12/31 by frog
 *  2003/02/22 , frog
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include "type.h"

#ifndef _WPACKET_H
#define _WPACKET_H

/////////////////////// Mac Frame ///////////////////////////////

/* + from ethereal-0.9.8 packet-prism.c */ 
/* a 802.11 value */
struct val_80211 {
    unsigned int did;
    unsigned short status, len;
    unsigned int data;
};
/* header attached during prism monitor mode */
typedef struct _PrismHdr {
    unsigned int msgcode, msglen;
    char devname[16];
    struct val_80211 hosttime, mactime, channel, rssi, sq, signal,
        noise, rate, istx, frmlen;
} PrismHdr ; 

typedef struct _MacHdr {
	OCTET2  frm_ctrl __attribute__ ((packed));
	OCTET2  duration __attribute__ ((packed));
	OCTET   addr1[6] __attribute__ ((packed));
	OCTET   addr2[6] __attribute__ ((packed));
	OCTET   addr3[6] __attribute__ ((packed));
	OCTET2  sequence __attribute__ ((packed));
	OCTET   addr4[6] __attribute__ ((packed));
} MacHdr ;

typedef struct _DataHdr {
	OCTET   dsap __attribute__ ((packed));
	OCTET   ssap __attribute__ ((packed));
	OCTET   ctrl __attribute__ ((packed));
	OCTET   org_code[3] __attribute__ ((packed));
	OCTET2  proto_id __attribute__ ((packed));
} DataHdr  ;


////////////////////////// IP Frame /////////////////////////////

typedef struct _IPHdr {
	u_int8_t ip_verhl;      /* version & header length */
	u_int8_t ip_tos;        /* type of service */
	u_int16_t ip_len;       /* datagram length */
	u_int16_t ip_id;        /* identification  */
	u_int16_t ip_off;       /* fragment offset */
	u_int8_t ip_ttl;        /* time to live field */
	u_int8_t ip_proto;      /* datagram protocol */
	u_int16_t ip_csum;      /* checksum */
	struct in_addr ip_src;  /* source IP */
	struct in_addr ip_dst;  /* dest IP */
} IPHdr;

typedef struct _UDPHdr {      
	u_int16_t uh_sport;
	u_int16_t uh_dport;
	u_int16_t uh_len;
	u_int16_t uh_chk;
} UDPHdr;

typedef struct _TCPHdr {
	u_int16_t th_sport;     /* source port */
	u_int16_t th_dport;     /* destination port */
	u_int32_t th_seq;       /* sequence number */
	u_int32_t th_ack;       /* acknowledgement number */
	u_int8_t th_offx2;     /* offset and reserved */
	u_int8_t th_flags;
	u_int16_t th_win;       /* window */
	u_int16_t th_sum;       /* checksum */
	u_int16_t th_urp;       /* urgent pointer */
} TCPHdr ;


////////////////////////// ruleset struct ////////////////////////

typedef struct _RIPBody {
	IPHdr	iphdr ;
	TCPHdr	tcphdr ;
	UDPHdr	udphdr ;
} RIPBody ;


typedef struct _RMgtbody {
	OCTET2	f_authnum ;
	OCTET2	f_authseq ;
	OCTET2	f_binterval ;
	OCTET2	f_capability;
	OCTET	f_currentap[6];
	OCTET2	f_linterval ;
	OCTET2	f_reason ;
	OCTET2	f_aid ;
	OCTET2	f_status ;
	OCTET	f_timestamp[8] ;
	//
	OCTET	v_ssid[32];
	OCTET	v_support[32];
	OCTET	v_fh[32];
	OCTET	v_ds[32];
	OCTET	v_cf[32];
	OCTET	v_tim[32];
	OCTET	v_ibss[32];
	OCTET	v_challenge[32];
} RMgtbody ;

typedef struct _RDatabody {
	OCTET	dsap ;
	OCTET	ssap ;
	OCTET	ctrl ;
	OCTET	org_code[3] ;
	OCTET2	proto_id ;

	RIPBody	ipbody ;

	int isip ;
	char fprint[32] ;
} RDatabody ;


typedef	struct _RPacket {
	MacHdr machdr ;
	RMgtbody mgtbody;
	RDatabody databody;
} RPacket ;


typedef	struct _Rule_Entry {
	unsigned int id ;
	unsigned char d_type ;
	int count ;
	int risk ;  // risk 0-5 , critical, more high, high, normal, less 
	int timer ;
	char desc[128];

	int  chklist[64] ; // check list
	RPacket	rpkt ;

} Rule_Entry ;



//  frame type of IEEE802.11
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
#define FC_MASK			0x00ff

#define MGT_ASSOC_REQ        	0x0000   /* Management - association request        */
#define MGT_ASSOC_RESP       	0x0010   /* Management - association response       */
#define MGT_REASSOC_REQ      	0x0020   /* Management - reassociation request      */
#define MGT_REASSOC_RESP     	0x0030   /* Management - reassociation response     */
#define MGT_PROBE_REQ        	0x0040   /* Management - Probe request              */
#define MGT_PROBE_RESP       	0x0050   /* Management - Probe response             */
#define MGT_BEACON           	0x0080   /* Management - Beacon frame               */
#define MGT_ATIM             	0x0090   /* Management - ATIM                       */
#define MGT_DISASS           	0x00A0   /* Management - Disassociation             */
#define MGT_AUTHENTICATION   	0x00B0   /* Management - Authentication             */
#define MGT_DEAUTHENTICATION 	0x00C0   /* Management - Deauthentication           */
#define CTRL_PS_POLL         	0x00a4   /* Control - power-save poll               */
#define CTRL_RTS             	0x00b4   /* Control - request to send               */
#define CTRL_CTS             	0x00c4   /* Control - clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 	0x00d4   /* Control - acknowledgement               */
#define CTRL_CFP_END         	0x00e4   /* Control - contention-free period end    */
#define CTRL_CFP_ENDACK      	0x00f4   /* Control - contention-free period end/ack */
#define DATA                 	0x0008   /* Data - Data                             */
#define DATA_CF_ACK          	0x0018   /* Data - Data + CF acknowledge            */
#define DATA_CF_POLL         	0x0028   /* Data - Data + CF poll                   */
#define DATA_CF_ACK_POLL     	0x0038   /* Data - Data + CF acknowledge + CF poll  */
#define DATA_NULL_FUNCTION   	0x0048   /* Data - Null function (no data)          */
#define DATA_CF_ACK_NOD      	0x0058   /* Data - CF ack (no data)                 */
#define DATA_CF_POLL_NOD     	0x0068   /* Data - Data + CF poll (No data)         */
#define DATA_CF_ACK_POLL_NOD 	0x0078   /* Data - CF ack + CF poll (no data)       */


#define FCFLG_TODS      	0x0100
#define FCFLG_FROMDS    	0x0200
#define FCFLG_MOREFRAG  	0x0400
#define FCFLG_RETRY     	0x0800
#define FCFLG_PWRMGT    	0x1000
#define FCFLG_MOREDATA  	0x2000
#define FCFLG_WEP       	0x4000
#define FCFLG_ORDER     	0x8000



// COOK method
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
#define COOK_FRAME_TYPE(x)	(((x) & 0xC) >> 2)
#define MGT_FRAME            	0x00       /* Frame type is management */
#define CONTROL_FRAME        	0x01       /* Frame type is control */
#define DATA_FRAME           	0x02       /* Frame type is Data */


// Management frame field
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
#define FIX_AUTHNUM         	0x00000001
#define FIX_AUTHSEQ         	0x00000002
#define FIX_BEACONINTERVAL  	0x00000004
#define FIX_CAPABILITY      	0x00000008
#define FIX_CURRENTAP       	0x00000010
#define FIX_LISTENINTERVAL  	0x00000020
#define FIX_REASON          	0x00000040
#define FIX_AID             	0x00000080
#define FIX_STATUS          	0x00000100
#define FIX_TIMESTAMP       	0x00000200

#define VAR_SSID            	0x00010000
#define VAR_SUPPORTEDRATES  	0x00020000
#define VAR_FHPARAM         	0x00040000
#define VAR_DSPARAM         	0x00080000
#define VAR_CFPARAM         	0x00100000
#define VAR_TIM             	0x00200000
#define VAR_IBSS            	0x00400000
#define VAR_CHALLENGE       	0x00800000  


// Unique id of rule set
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
#define CHK_ID                      1
#define CHK_DTYPE                   2
#define CHK_COUNT                   3
#define CHK_RISK                    4
#define CHK_TIMER                   5
#define CHK_DESC                    6

#define	CHK_PKT_TYPE                10000
#define	CHK_PKT_TODSFLG             10001
#define	CHK_PKT_FROMDSFLG           10002
#define	CHK_PKT_MOREFRAGFLG         10003
#define	CHK_PKT_RETRYFLG            10004
#define	CHK_PKT_PWRMGTFLG           10005
#define	CHK_PKT_MOREDATFLG          10006
#define	CHK_PKT_WEPFLG              10007
#define	CHK_PKT_ORDERFLG            10008
#define	CHK_PKT_DURATION            10009
#define	CHK_PKT_ADDR1               10010
#define	CHK_PKT_ADDR2               10011
#define	CHK_PKT_ADDR3               10012
#define	CHK_PKT_SEQ                 10013
#define	CHK_PKT_ADDR4               10014

#define	CHK_PKT_MGT_AUTHNUM         10100
#define	CHK_PKT_MGT_AUTHSEQ         10101
#define	CHK_PKT_MGT_BEACONINTERVAL  10102
#define	CHK_PKT_MGT_CAPABILITY      10103
#define	CHK_PKT_MGT_CURRENTAP       10104
#define	CHK_PKT_MGT_LISTENINTERVAL  10105
#define	CHK_PKT_MGT_REASONCODE      10106
#define	CHK_PKT_MGT_ASSOCID         10107
#define	CHK_PKT_MGT_STATUSCODE      10108
#define	CHK_PKT_MGT_TIMESTAMP       10109
#define	CHK_PKT_MGT_SSID            10110
#define	CHK_PKT_MGT_SUPPORTEDRATES  10111
#define	CHK_PKT_MGT_FHPARAM         10112
#define	CHK_PKT_MGT_DSPARAM         10113
#define	CHK_PKT_MGT_CFPARAM         10114
#define	CHK_PKT_MGT_IBSSPARAM       10115
#define	CHK_PKT_MGT_TIM             10116
#define	CHK_PKT_MGT_CHALLENGE       10117
#define	CHK_PKT_DAT_DSAP            10200
#define	CHK_PKT_DAT_SSAP            10201
#define	CHK_PKT_DAT_CTRL            10202
#define	CHK_PKT_DAT_ORGCODE         10203
#define	CHK_PKT_DAT_PROTO           10204

#define	CHK_PKT_DAT_IP_PROTO        20000
#define	CHK_PKT_DAT_IP_SRCIP        20001
#define	CHK_PKT_DAT_IP_DSTIP        20002
#define	CHK_PKT_DAT_IP_TCP_SRCPORT  20100
#define	CHK_PKT_DAT_IP_TCP_DSTPORT  20101
#define	CHK_PKT_DAT_IP_UDP_SRCPORT  20200
#define	CHK_PKT_DAT_IP_UDP_DSTPORT  20201
                                         
#define	CHK_PKT_MGTFPRINT           9999 
#define	CHK_PKT_DATFPRINT           9998 
#define	CHK_PKT_CTRLFPRINT          9997 
#define	CHK_PKT_IPFPRINT            9996 
#define	CHK_PKT_TCPFPRINT           9995 
#define	CHK_PKT_UDPFPRINT           9994 


#endif
