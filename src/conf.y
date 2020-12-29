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
/* $Id: conf.y,v 1.2 2004/06/23 09:14:18 seunghyun Exp $ */
/****************************************************************************
  *
  * conf.y
  *
  * config yacc grammar
  *
  * 2003/03/11 , frog
  *
  ***************************************************************************/

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "symnum.h"
#include "cio.h"

	
int conf_yylex(void) ;
int conf_yyerror(char *str);

#define DebugMessage(str) do{ \
	printf("YACC : [%s]\n", str ) ; \
}while(0) 

#define SysConfigError(str) do{ \
	fprintf(stderr, "Config Error : %s ", str ); \
	exit(-1); \
}while(0) 

//#define DebugMessage(str) do {} while(0) 
//#define DebugMsgExpression() do {} while(0) 


/* global variables */
extern Config gConfig ;
int conf_vartype ;


/* local variables */
static APMacList	TempAPList ;
static int TempAPNum ;

void SetConfigVariable( char* field,  char *var, int vartype ) ;

%}

%start root
%token MACADDR
%token STRING
%token SWITCH
%token VARNAME

%%

root : expr_list {
	DebugMessage("root!!" );
}
;

expr_list :  expr expr_list | expr {
	DebugMessage("statment!!" );
}
;

expr : VARNAME value {
       DebugMessage("expr!!");
       printf("\n\t**** %s %s ****\n\n", (char*)$1, (char*)$2 ); 
       SetConfigVariable( (char*)$1, (char*)$2, conf_vartype );
}
;

value :  STRING | SWITCH | maclist
;

maclist : macentry maclist | macentry  
;

macentry : MACADDR {
		printf("mac found %s, (%d)\n", (char*)$1, TempAPNum ) ;

		sscanf( (char*)$1, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", \
				&TempAPList.mac[TempAPNum][0], \
				&TempAPList.mac[TempAPNum][1], \
				&TempAPList.mac[TempAPNum][2], \
				&TempAPList.mac[TempAPNum][3], \
				&TempAPList.mac[TempAPNum][4], \
				&TempAPList.mac[TempAPNum][5] \
		      );

		TempAPNum++ ;


}
;


%%






int LoadConfig(char *filename )
{
	if ( InitConfigInput( filename ) < 0 ){
		perror("InitConfigInput");
		exit(0);
	}
	gConfig.TrustAPNum = 0 ;

	conf_yyparse();

	return 1;
}

void 
SetConfigVariable( char* field,  char *var, int vartype )
{
	int config_id = 0 ;

	config_id = GetConfigFieldId( field ) ;

	if ( config_id < 0 ) {
		SysConfigError("GetConfigVarId()");
	}

	switch( config_id ) {
		case CNF_SERVERNAME: 
			if ( vartype != STRING )
				SysConfigError("Argument are not string");

			snprintf( gConfig.ServerName, MAX_OPTSTR, "%s", var ); 
			break;       

		case CNF_GARUDAROOT: 
			if ( vartype != STRING )
				SysConfigError("Argument are not string");

			snprintf( gConfig.GarudaRoot, MAX_PATH, "%s", var ); 
			break;       

		case CNF_DEVICENAME: 
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");

			snprintf( gConfig.DeviceName, MAX_OPTSTR, "%s", var );
			gConfig.dfn = 1 ;
			break;       

		case CNF_DEAMONMODE:
			if ( vartype != SWITCH )
				SysConfigError("Argument are not switch ");

			if ( !strcmp( var, "On") )
				gConfig.mode_deamon = 1 ;
			break; 

		case CNF_SIMULATIONMODE:
			if ( vartype != SWITCH )
				SysConfigError("Argument are not switch ");

			if ( !strcmp( var, "On") )
				gConfig.off = 1 ;
			break;       

		case CNF_LOGDIRECTORY:
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.LogDirectory, MAX_OPTSTR, "%s", var );
			gConfig.ld =1 ;
			break;       

		case CNF_FILTERFILE: 
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.FilterFilename, MAX_OPTSTR, "%s", var );
			gConfig.ffn = 1 ;
			break;       

		case CNF_RULEFILE :   
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.RuleFilename, MAX_OPTSTR, "%s", var );
			gConfig.rfn = 1 ;
			break;       

		case CNF_SAMPLEFILE : 
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.SampleFilename, MAX_OPTSTR, "%s", var );
			gConfig.sfn = 1 ;
			break;       

		case CNF_TRUSTAPLIST:
			gConfig.TrustAPList = TempAPList ;
			gConfig.TrustAPNum = TempAPNum ;

			break;       

		case CNF_MYSQLUSE :   
			if ( vartype != SWITCH )
				SysConfigError("Argument are not switch ");

			if ( !strcmp( var, "On") )
				gConfig.mysql_use = 1 ;
			break; 


		case CNF_MYSQLHOST :   
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.MysqlHost, MAX_OPTSTR, "%s", var );
			break;

		case CNF_MYSQLUSER :   
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.MysqlUser, MAX_OPTSTR, "%s", var );
			break;


		case CNF_MYSQLPASS :   
			if ( vartype != STRING )
				SysConfigError("Argument are not string ");
			
			snprintf( gConfig.MysqlPass, MAX_OPTSTR, "%s", var );
			break;



		default:
			fprintf(stderr, "Config parse error" );
			SysErrorExit("SetConfigVariable");

	}

	return ;
}
