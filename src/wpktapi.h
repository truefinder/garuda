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
/* $Id: wpktapi.h,v 1.2 2004/06/25 08:40:22 seunghyun Exp $ */


/* 
 * wpktapi.h
 *
 * last update: 
 *
 */
#ifndef	_WPKTAPI_H
#define	_WPKTAPI_H

/////////////////////// Definition /////////////////////////////////////
////////////////////////////////////////////////////////////////////////

// fixed variable define
#define	AUTHNUM			1
#define	AUTHSEQ			2
#define BEACONINTERVAL		3
#define	CAPABILITY		4
#define CURRENTAP		5
#define LISTENINTERVAL		6
#define REASONCODE		7
#define ASSOCID			8
#define	STATUSCODE		9
#define TIMESTAMP		10

// fixed variable size define
#define SIZE_AUTHNUM		2
#define	SIZE_AUTHSEQ		2
#define	SIZE_BEACONINTERVAL	2
#define	SIZE_CAPABILITY		2
#define SIZE_CURRENTAP		6
#define SIZE_LISTENINTERVAL	2
#define SIZE_REASONCODE		2
#define SIZE_ASSOCID		2
#define	SIZE_STATUSCODE		2
#define SIZE_TIMESTAMP		8

// element variable define
#define SSID			1
#define SUPPORTEDRATES		2
#define	FHPARAM			3
#define DSPARAM			4
#define CFPARAM			5
#define	TIM			6
#define IBSSPARAM		7
#define CHALLENGETXT		8


// element id define
#define EID_SSID		0
#define EID_SUPPORTEDRATES	1
#define	EID_FHPARAM		2
#define EID_DSPARAM		3
#define EID_CFPARAM		4
#define	EID_TIM			5
#define EID_IBSSPARAM		6
#define EID_RESERVED0		7
#define EID_RESERVED15		7
#define EID_CHALLENGETXT	16
#define EID_RESERVED32		32
#define EID_RESERVED255		255


// get element by element id 
typedef struct _Mgt_Element  {
	int eid ;
	int len ;
	char *ptr ;
} Mgt_Element ;


///////////////// External Functions /////////////////////////////////
//////////////////////////////////////////////////////////////////////

unsigned short int get_frmtype ( MacHdr *mp ) ;
void 	wnet_mtos( char *pdst, const char *psrc );
void 	wnet_stom( char *pdst, const char *psrc );

char *	get_mgt_vstart( MacHdr *mp, int len, int *lastlen ) ;
char *	get_mgt_fstart( MacHdr *mp, int len) ;
char *	get_mgt_fvalue( MacHdr *mp,  int len , int fixed_id ) ;
int	get_mgt_vvalue( MacHdr *mp , int len, int element_id, Mgt_Element *e_ptr  ) ;

char *	get_srcmac ( MacHdr *mp );
char *	get_dstmac ( MacHdr *mp );
char *	get_bssidmac ( MacHdr *mp );

int is_unofficial_datfrm( MacHdr *mp );
struct in_addr * get_dat_srcip( MacHdr *mp );
struct in_addr * get_dat_dstip( MacHdr *mp );
unsigned short int  get_dat_srcport( MacHdr *mp );
unsigned short int  get_dat_dstport( MacHdr *mp );

#endif

