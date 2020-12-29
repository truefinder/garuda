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
/* $Id: conf.l,v 1.2 2004/06/23 09:14:18 seunghyun Exp $ */

%{
/****************************************************************************
  *
  * conf.l
  *
  * set gConfig from config file
  * we added prefix "conf_yy" into yy*** functions 
  * so yylex() converted to conf_yylex()  
  *
  *
  ***************************************************************************/
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "confyacc.h"
#include "cio.h"


/* extern variables */
extern	int conf_vartype ;

static char comment_buf[4096];
static int i; 
static int ch ;
static char *tmp ;


#define DebugMessage(str) do { \
	printf("Lex  : (%s) %s\n", str, conf_yytext ); \
	fflush( stdout ); \
} while(0)

#define DebugMessageComment(str) do { \
	printf("Lex  : (%s) %s\n", str, comment_buf ) ; \
	fflush( stdout) ; \
} while(0)

/*
#define DebugMessage(str) do {} while(0)
#define DebugMessageComment(str) do {} while(0)
*/


%}

hex	[a-fA-F0-9]
macaddr	{hex}{hex}:{hex}{hex}:{hex}{hex}:{hex}{hex}:{hex}{hex}:{hex}{hex}


%%




ServerName |
GarudaRoot |
DeviceName |
DeamonMode |
SimulationMode |
TrustAPList |
LogDirectory |
FilterFile |
RuleFile |
SampleFile |
MysqlUse |
MysqlHost |
MysqlUser |
MysqlPass {	
	DebugMessage("varname");
	(char*)conf_yylval = strdup(conf_yytext) ;
	return VARNAME;
}

{macaddr} {
	DebugMessage("macaddr");
	(char*)conf_yylval = strdup(conf_yytext) ;
	conf_vartype=MACADDR ;
	return MACADDR;
}


\"[0-9a-zA-Z.,_\-+()*&^!@#$%~`/ ]+\" {
	DebugMessage("string ");
	tmp = (char*)strndup(conf_yytext, (size_t)conf_yyleng-1);
	(char*)conf_yylval = strdup( &tmp[1]) ;

	conf_vartype=STRING ;
	return STRING ;
}

On |
Off  {
	DebugMessage("switch " );
	(char*)conf_yylval = strdup(conf_yytext) ;
	conf_vartype = SWITCH ;
	return SWITCH ;
}


# {
	/* comment processing */ 
	i = 0 ;
	while( (ch = input()) != '\n' ) {
		if ( i < sizeof(comment_buf) )
		comment_buf[i++] = ch ;

		if ( ch == '\0' ) {
			DebugMessage("End of file in comment");
		}
	}
	unput(ch);
	DebugMessageComment("comment");

	memset( comment_buf, '\0', sizeof(comment_buf ) ) ;

}

[\n\t ]+        ; /* white space ignored */



%%


void conf_yyerror(void)
{
	printf("error at %s\n", conf_yytext) ;
}

int conf_yywrap(void) 
{ 
	// to avoid multiple defination
	// we use only one config file
	// general yywrap() returns 1 
	return 1;
}


int
InitConfigInput( char *filename )
{
	FILE *fp ;

	fp = fopen( filename, "r");
	if ( fp == NULL ) {
		perror("fopen");
		return -1 ;
	}

	conf_yyin = fp ;
	return 1 ;

}


