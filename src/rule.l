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
/* $Id: rule.l,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */
%{
/****************************************************************************
  *
  * rule.l 
  *
  * read rule set from rule.txt and return each tokens to yyparse()
  *
  *
  ***************************************************************************/
#include "ruleyacc.h"
#include <ctype.h>
#include <stdio.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "wpacket.h"
#include "config.h"
#include "rule.h"
#include "cio.h"


/*** global variables ***/
extern unsigned int var_type ;
//extern char * yylval ; 


/*** local variables ***/
char *tmp ;
static char ch ;
static int i ;
static char comment_buf[256];
%}


%%

, { 
	DebugMessage("LEX -> %10s Found : \t %s\n","COMMA", yytext); 
	return COMMA ; 
}

; {
	DebugMessage("LEX -> %10s Found : \t %s\n","SEMICOLON",yytext); 
	return SEMICOLON ; 
}

: {
	DebugMessage("LEX -> %10s Found : \t %s\n","COLON",yytext); 
	return COLON ; 
}

# { 	
	/* comment  */
	i = 0 ;
	while( (ch = input()) != '\n' ) {
		if ( i < sizeof(comment_buf) ) 
			comment_buf[i++] = ch ;

		if ( ch == '\0' ) {
			DebugMessage("End of file in comment"); 
		}
	}
	unput(ch);
	
	DebugMessage("LEX -> %10s Found : \t %s\n","COMMENT", comment_buf);
	memset( comment_buf, '\0', sizeof(comment_buf ) ) ;

}



match |
count |
status { 
	DebugMessage("LEX -> %10s Found : \t %s\n","ACTION",yytext); 
	(char*)yylval = strdup(yytext) ;
	return ACTION ; 
}

0x[0-9a-fA-F] { 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEX1",yytext); 
	(char*)yylval = strdup(yytext) ;
	var_type = HEX1 ;
	return HEX1; 
}

0x[0-9a-fA-F][0-9a-fA-F] { 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEX1",yytext); 
	(char*)yylval = strdup(yytext) ;
	var_type = HEX1 ;
	return HEX1; 
}

0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]	{ 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEX2",yytext); 
	(char*)yylval = strdup(yytext) ;
	var_type = HEX2 ;
	return HEX2; 
}

0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]	{ 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEX3",yytext); 
	(char*)yylval = strdup(yytext) ;
	var_type = HEX3 ;
	return HEX3; 
}


0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F] { 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEX4",yytext); 
	(char*)yylval = strdup(yytext) ;
	var_type = HEX4 ;
	return HEX4; 
}

"|"([0-9a-fA-F][0-9a-fA-F]" "?)+"|"	{ 
	DebugMessage("LEX -> %10s Found : \t %s\n","HEXES",yytext); 
	//(char*)yylval = strdup(yytext) ;
	tmp = (char*)strndup(yytext, (size_t)yyleng-1);
	(char*)yylval = strdup( &tmp[1]) ;

	var_type = HEXES ;
	return HEXES; 
}


\"[0-9a-zA-Z.,_\-+()*&^!@#$%~` ]+\"	{ 
	DebugMessage("LEX -> %10s Found : \t %s\n","STRING",yytext); 
	tmp = (char*)strndup(yytext, (size_t)yyleng-1);
	(char*)yylval = strdup( &tmp[1]) ;

	var_type = STRING ;
	return STRING; 
}



True |
False {
	DebugMessage("LEX -> %10s Found : \t %s\n","BOOL",yytext);
	(char*)yylval = strdup( yytext ) ;
	var_type = BOOL ;
	return BOOL; 
}


Id  |
Risk |
Desc |
Count |
Timer |
Pkt.type |
Pkt.todsflg |
Pkt.fromdsflg |
Pkt.morefragflg |
Pkt.retryflg |
Pkt.pwrmgtflg |
Pkt.moredatflg |
Pkt.wepflg |
Pkt.orderflg |
Pkt.duration |
Pkt.addr1 |
Pkt.addr2 |
Pkt.addr3 |
Pkt.seq |
Pkt.addr4 |
Pkt.mgt.authnum |
Pkt.mgt.authseq |
Pkt.mgt.beaconinterval |
Pkt.mgt.capability |
Pkt.mgt.currentap |
Pkt.mgt.listeninterval |
Pkt.mgt.reasoncode |
Pkt.mgt.associd |
Pkt.mgt.statuscode |
Pkt.mgt.timestamp |
Pkt.mgt.ssid |
Pkt.mgt.supportedrates |
Pkt.mgt.fhparam |
Pkt.mgt.dsparam |
Pkt.mgt.cfparam |
Pkt.mgt.ibssparam |
Pkt.mgt.tim |
Pkt.mgt.challenge |
Pkt.dat.dsap |
Pkt.dat.ssap |
Pkt.dat.ctrl |
Pkt.dat.orgcode |
Pkt.dat.proto |
Pkt.dat.ip.proto |
Pkt.dat.ip.srcip |
Pkt.dat.ip.dstip |
Pkt.dat.ip.tcp.srcport |
Pkt.dat.ip.tcp.dstport |
Pkt.dat.ip.udp.srcport |
Pkt.dat.ip.udp.dstport |
Pkt.mgtfprint |
Pkt.datfprint |
Pkt.ctrlfprint |
Pkt.ipfprint |
Pkt.tcpfprint |
Pkt.udpfprint { 
	DebugMessage("LEX -> %10s Found : \t %s\n","VARNAME",yytext);
	(char*)yylval = (char*)strdup(yytext) ;
	return VARNAME; 
}

MGT_ASSOC_REQ  |      
MGT_ASSOC_RESP  |     
MGT_REASSOC_REQ  |    
MGT_REASSOC_RESP  |   
MGT_PROBE_REQ    |    
MGT_PROBE_RESP  |     
MGT_BEACON  |        
MGT_ATIM  |           
MGT_DISASS  |         
MGT_AUTHENTICATION  | 
MGT_DEAUTHENTICATION  | 
CTRL_PS_POLL  | 
CTRL_RTS  |           
CTRL_CTS  |           
CTRL_ACKNOWLEDGEMENT  |
CTRL_CFP_END  |       
CTRL_CFP_ENDACK  |    
DATA  |               
DATA_CF_ACK  |        
DATA_CF_POLL  |       
DATA_CF_ACK_POLL  |   
DATA_NULL_FUNCTION  | 
DATA_CF_ACK_NOD  |    
DATA_CF_POLL_NOD  |   
DATA_CF_ACK_POLL_NOD  {
	DebugMessage("LEX -> %10s Found : \t %s\n","DEFSYM",yytext);
	(char*)yylval = (char*)strdup(yytext) ;
	var_type = DEFSYM ;
	return DEFSYM; 
}

[\n\t ]+	; /* white space ignored */

%%

void yyerror(void)
{
	DebugMessage("Error at :");
	DebugMessage(yytext);
	SysErrorMessage("yyerror() : ");

	//printf("error at %s\n", yytext) ;
}



int 
InitLexInput( char *filename )
{
	FILE *fp ;
	fp = fopen( filename, "r");
	if ( fp == NULL ) {
		SysErrorMessage("InitLexInput() : cannot open file");
		return ERROR ;
	}

	yyin = fp ;
	return TRUE;
}


