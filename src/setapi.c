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
/* $Id: setapi.c,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */

/****************************************************************************
  *
  * setapi.c
  *
  * this module is used to set various values in rule[]
  *
  * last update :
  * 2004/02/23 , frog
  *
  ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ruleyacc.h"
#include "type.h"
#include "wpacket.h"
#include "config.h"

typedef struct _SymList {
	char field[32];
	unsigned int selnum ;
} SymList ;

/*** global variables ***/
extern int chkid  ;
extern unsigned int var_type ;
extern Rule_Entry rule[128];



SymList symList[32] = {
    {"MGT_ASSOC_REQ"        ,0x0000},
    {"MGT_ASSOC_RESP"       ,0x0010},
    {"MGT_REASSOC_REQ"      ,0x0020},
    {"MGT_REASSOC_RESP"     ,0x0030},
    {"MGT_PROBE_REQ"        ,0x0040},
    {"MGT_PROBE_RESP"       ,0x0050},
    {"MGT_BEACON"           ,0x0080},
    {"MGT_ATIM"             ,0x0090},
    {"MGT_DISASS"           ,0x00A0},
    {"MGT_AUTHENTICATION"   ,0x00B0},
    {"MGT_DEAUTHENTICATION" ,0x00C0},
    {"CTRL_PS_POLL"         ,0x00a4},
    {"CTRL_RTS"             ,0x00b4},
    {"CTRL_CTS"             ,0x00c4},
    {"CTRL_ACKNOWLEDGEMENT" ,0x00d4},
    {"CTRL_CFP_END"         ,0x00e4},
    {"CTRL_CFP_ENDACK"      ,0x00f4},
    {"DATA"                 ,0x0008},
    {"DATA_CF_ACK"          ,0x0018},
    {"DATA_CF_POLL"         ,0x0028},
    {"DATA_CF_ACK_POLL"     ,0x0038},
    {"DATA_NULL_FUNCTION"   ,0x0048},
    {"DATA_CF_ACK_NOD"      ,0x0058},
    {"DATA_CF_POLL_NOD"     ,0x0068},
    {"DATA_CF_ACK_POLL_NOD" ,0x0078},
    {"NONE"                 ,-1},
} ;


///////////// Functions /////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

unsigned int 
get_symid ( char *sym ) 
{
	int i ;
	for ( i =0 ; i < 32 ; i++ ) {
		if ( symList[i].selnum < 0 )
			return 0 ;

		if ( ! strcmp( symList[i].field, sym ) ) {
			return symList[i].selnum ;
		}
	}

	return 0;
}


void 
set_hex1( int *hex1, char *value )
{
	*hex1 = strtol(value, NULL, 16) ;
	return ;
}

void 
set_hex2( int *hex2, char *value ) 
{
	*hex2 = strtol(value, NULL, 16) ;
	return ;
}

void 
set_hex3( int *hex3, char *value ) 
{
	*hex3 = strtol(value, NULL, 16) ;
	return ;
}

void 
set_hex4( int *hex4, char *value ) 
{
	*hex4 = strtol(value, NULL, 16) ;
	return ;
}

void 
set_string( char *str, char *value )
{
	snprintf( str, 32, value );
	return ;
}

void 
set_bool ( char *str , char *value )
{
	return ;
}

void set_hexes( char *hexes, char *value )
{
	int i=0 , j=0 ;
	int n ;
	n = strlen( value );

	for ( ; j < n  ;i+=3, j++ ) {
		sscanf( (char*)&value[i], "%hhx ", (char*)&hexes[j] );
	}

	return ;
}

void set_defsym( char *defsym, char *value )
{
	*defsym = get_symid( value );
	return ;
}



void 
do_set( void *member, char *value, int type ) 
{
	switch( type ){
		case HEX1:
			set_hex1((int*) member, value );
			break;

		case HEX2:
			set_hex2((int*) member, value );
			break;

		case HEX3:
			set_hex3((int*) member, value );
			break;

		case HEX4:
			set_hex4((int*) member, value );
			break;

		case HEXES:
			set_hexes((char*) member, value );
			break;

		case STRING:
			set_string((char*) member, value );
			break;

		case BOOL:
			set_bool( (char*) member, value ) ;
			break;

		case DEFSYM:
			set_defsym((char*) member, value );
			break;

	}

	return ;
}

int 
set_var( int order ,unsigned int id, char *value, unsigned int type )
{
	switch ( id ) {
		/* rule info */
		case CHK_ID:
			do_set( &rule[order].id , value, type );
			break;
	
		case CHK_DTYPE:
			do_set( &rule[order].d_type, value, type );
			//rule[order].d_type = 1 ;
			break;

		case CHK_RISK:
			do_set( &rule[order].risk, value, type );
			// rule[order].risk = strtol(value, NULL, 16 );
			break;

		case CHK_COUNT:
			do_set( &rule[order].count, value, type);
			//rule[order].count = strtol(value, NULL, 16 );
			break;

		case CHK_TIMER:
			do_set(&rule[order].timer, value, type);
			//rule[order].timer = strtol(value, NULL, 16 );
			break;
			
		case CHK_DESC:
			do_set( &rule[order].desc, value, type );
			//snprintf( rule[order].desc, 32, value );
			break;

		/* real packet check */

		// mac header secion 
		case CHK_PKT_TYPE     : 
			do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
			//rule[order].rpkt.machdr.frm_ctrl = get_symid( value );
			rule[order].chklist[chkid++] = CHK_PKT_TYPE ;
			break;

		case CHK_PKT_TODSFLG     : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_TODS  ;
				rule[order].chklist[chkid++] = CHK_PKT_TODSFLG ; 
			}
			break;

		case CHK_PKT_FROMDSFLG   : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_FROMDS ;
				rule[order].chklist[chkid++] = CHK_PKT_FROMDSFLG ;
			}
			break;

		case CHK_PKT_MOREFRAGFLG  : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_MOREFRAG ;
				rule[order].chklist[chkid++] = CHK_PKT_MOREFRAGFLG ;
			}
			break;

		case CHK_PKT_RETRYFLG    : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type); 
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_RETRY ;
				rule[order].chklist[chkid++] = CHK_PKT_RETRYFLG ;
			}
			break;

		case CHK_PKT_PWRMGTFLG   :
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type); 
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_PWRMGT ;
				rule[order].chklist[chkid++] = CHK_PKT_PWRMGTFLG ;
			}
			break;

		case CHK_PKT_MOREDATFLG  : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_MOREDATA ;
				rule[order].chklist[chkid++] = CHK_PKT_MOREDATFLG ;
			}
			break;

		case CHK_PKT_WEPFLG      : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_WEP ;
				rule[order].chklist[chkid++] = CHK_PKT_WEPFLG ;
			}
			break;

		case CHK_PKT_ORDERFLG    : 
			if ( !strcmp("True", value ) ) {
				//do_set( &rule[order].rpkt.machdr.frm_ctrl, value, type);
				rule[order].rpkt.machdr.frm_ctrl |= FCFLG_ORDER ;
				rule[order].chklist[chkid++] = CHK_PKT_ORDERFLG ;
			}
			break;

		case CHK_PKT_DURATION    : 
			do_set( &rule[order].rpkt.machdr.duration , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DURATION  ;
			break;
		case CHK_PKT_ADDR1       : 
			do_set( &rule[order].rpkt.machdr.addr1 , value, type );
			rule[order].chklist[chkid++] =  CHK_PKT_ADDR1 ;
			break;
		case CHK_PKT_ADDR2       : 
			do_set( &rule[order].rpkt.machdr.addr2 , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_ADDR2  ;
			break;
		case CHK_PKT_ADDR3       : 
			do_set( &rule[order].rpkt.machdr.addr3 , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_ADDR3 ;
			break;
		case CHK_PKT_SEQ         : 
			do_set( &rule[order].rpkt.machdr.sequence , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_SEQ  ;
			break;
		case CHK_PKT_ADDR4       : 
			do_set( &rule[order].rpkt.machdr.addr4 , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_ADDR4 ;
			break;

		// mgt fixed filed 
		case CHK_PKT_MGT_AUTHNUM   : 
			do_set( &rule[order].rpkt.mgtbody.f_authnum , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_AUTHNUM ;
			break;
		case CHK_PKT_MGT_AUTHSEQ   : 
			do_set( &rule[order].rpkt.mgtbody.f_authseq, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_AUTHSEQ ;
			break;
		case CHK_PKT_MGT_BEACONINTERVAL : 
			do_set( &rule[order].rpkt.mgtbody.f_binterval , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_BEACONINTERVAL ;
			break;
		case CHK_PKT_MGT_CAPABILITY: 
			do_set( &rule[order].rpkt.mgtbody.f_capability , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_CAPABILITY ;
			break;
		case CHK_PKT_MGT_CURRENTAP : 
			do_set( &rule[order].rpkt.mgtbody.f_currentap , value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_CURRENTAP ;
			break;
		case CHK_PKT_MGT_LISTENINTERVAL : 
			break;
		case CHK_PKT_MGT_REASONCODE    : 
			break;
		case CHK_PKT_MGT_ASSOCID       : 
			break;
		case CHK_PKT_MGT_STATUSCODE    : 
			break;
		case CHK_PKT_MGT_TIMESTAMP : 
			break;

		// variable element section
		case CHK_PKT_MGT_SSID      : 
			do_set(  &rule[order].rpkt.mgtbody.v_ssid, value, type );
			//snprintf( rule[order].rpkt.mgtbody.v_ssid, 32, value );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_SSID ;
			break;

		case CHK_PKT_MGT_SUPPORTEDRATES   :
			do_set(  &rule[order].rpkt.mgtbody.v_support, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_SUPPORTEDRATES ;
			break;
		case CHK_PKT_MGT_FHPARAM :
			do_set(  &rule[order].rpkt.mgtbody.v_fh, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_FHPARAM ;
			break;
		case CHK_PKT_MGT_DSPARAM        : 
			do_set(  &rule[order].rpkt.mgtbody.v_ds, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_DSPARAM ;
			break;
		case CHK_PKT_MGT_CFPARAM        :
			do_set(  &rule[order].rpkt.mgtbody.v_cf, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_CFPARAM ;
			break;
		case CHK_PKT_MGT_TIM       :
			do_set(  &rule[order].rpkt.mgtbody.v_tim, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_TIM ;
			break;
		case CHK_PKT_MGT_IBSSPARAM      : 
			do_set(  &rule[order].rpkt.mgtbody.v_ibss, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_IBSSPARAM ;
			break;
		case CHK_PKT_MGT_CHALLENGE :
			do_set(  &rule[order].rpkt.mgtbody.v_challenge, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_MGT_CHALLENGE ;
			break;


		// data frame llc section
		case CHK_PKT_DAT_DSAP       : 
			do_set(  &rule[order].rpkt.databody.dsap, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DAT_DSAP ; 
			break;
		case CHK_PKT_DAT_SSAP       :
			do_set(  &rule[order].rpkt.databody.ssap, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DAT_SSAP ; 
			break;
		case CHK_PKT_DAT_CTRL       :
			do_set(  &rule[order].rpkt.databody.ctrl, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DAT_CTRL ; 
			break;
		case CHK_PKT_DAT_ORGCODE    :
			do_set(  &rule[order].rpkt.databody.org_code, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DAT_ORGCODE ; 
			break;
		case CHK_PKT_DAT_PROTO    :
			do_set(  &rule[order].rpkt.databody.proto_id, value, type );
			rule[order].chklist[chkid++] = CHK_PKT_DAT_PROTO ; 
			break;
		case CHK_PKT_DAT_IP_PROTO        : break;
		case CHK_PKT_DAT_IP_SRCIP        : break;
		case CHK_PKT_DAT_IP_DSTIP        : break;
		case CHK_PKT_DAT_IP_TCP_SRCPORT     : break;
		case CHK_PKT_DAT_IP_TCP_DSTPORT     : break;
		case CHK_PKT_DAT_IP_UDP_SRCPORT     : break;
		case CHK_PKT_DAT_IP_UDP_DSTPORT     : break;

		case CHK_PKT_MGTFPRINT      : break;
		case CHK_PKT_DATFPRINT     : 
			do_set( &rule[order].rpkt.databody.fprint,  value, type ); 
			//snprintf( rule[order].rpkt.databody.fprint, 32, value ); 
			rule[order].chklist[chkid++] = CHK_PKT_DATFPRINT ;
			break;
		case CHK_PKT_CTRLFPRINT     : break;
		case CHK_PKT_IPFPRINT       : break;
		case CHK_PKT_TCPFPRINT      : break;
		case CHK_PKT_UDPFPRINT      : break;
		default :
			break;
	}
	return 0 ;

}
