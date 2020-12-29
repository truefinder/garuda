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
/* $Id: statistics.h,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */
/* statistic.h */

#ifndef _STATISTICS_H
#define _STATISTICS_H

#include "type.h"


typedef struct _Mac {
	unsigned int mgt_total ;
	unsigned int data_total ;
	unsigned int ctrl_total ;
	unsigned int mgt_assoc_req        ;
	unsigned int mgt_assoc_resp       ;
	unsigned int mgt_reassoc_req      ;
	unsigned int mgt_reassoc_resp     ;
	unsigned int mgt_probe_req        ;
	unsigned int mgt_probe_resp       ;
	unsigned int mgt_beacon           ;
	unsigned int mgt_atim             ;
	unsigned int mgt_disass           ;
	unsigned int mgt_authentication   ;
	unsigned int mgt_deauthentication ;
	unsigned int ctrl_ps_poll         ;
	unsigned int ctrl_rts             ;
	unsigned int ctrl_cts             ;
	unsigned int ctrl_acknowledgement ;
	unsigned int ctrl_cfp_end         ;
	unsigned int ctrl_cfp_endack      ;
	unsigned int data                 ;
	unsigned int data_cf_ack          ;
	unsigned int data_cf_poll         ;
	unsigned int data_cf_ack_poll     ;
	unsigned int data_null_function   ;
	unsigned int data_cf_ack_nod      ;
	unsigned int data_cf_poll_nod     ;
	unsigned int data_cf_ack_poll_nod ;
} Mac ;

typedef struct _Tcpip {
	unsigned int ip_total	 ;
	unsigned int tcp	 ;
	unsigned int udp	 ;
	unsigned int other	 ;
} Tcpip ;

typedef struct _Station {
	unsigned int macpkt_total ;
	unsigned int ippkt_total ;
	OCTET mac[6] ;
	unsigned int ip ;
} Station ;

typedef struct _Statistics {
	time_t starttime ;
	Mac mac ;
	Tcpip tcpip ;
	Station statable[1024];

} Statistics;


void do_statistics( char *machdr, int len );
void LogStatistics( void );

#endif
