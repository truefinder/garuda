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
/* $Id: rule.y,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */

/****************************************************************************
  *
  * rule.y
  *
  * Yacc assesment for rule set, shift/reduce method rhs 
  * fill rule[MAX_ENTRY] which will be used detecting
  * InitRule() -> LoadRule() << rule.txt -> yyparse() => rule[MAX_ENTRY]
  * 
  *
  ***************************************************************************/

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"
#include "wpacket.h"	
#include "config.h"
#include "cio.h"
#include "mesg.h"
#include "rule.h"
#include "garuda.h"
#include "symnum.h"
#include "setapi.h"


/*** Global variables ***/
extern Rule_Entry rule[MAX_RULE];
unsigned int var_type  = 0 ;
int chkid = 0 ;
extern Config gConfig ;


/*** local variables ***/
static int r_order = 0 ;
static int success_flg = 0 ;
static char *rtype[4] = { "other", "match", "count", "status", } ;
int rtype_id = 0 ;

/*** external functions ***/
extern int InitLexInput(char *filename); // from rule.l


/*** internal functions ***/
int yylex(void);
int yyerror(char *str );
int GetActionType( char *actstr )  ;


%}
 

%start	root
%token	ACTION
%token	HEX1
%token	HEX2
%token	HEX3
%token	HEX4
%token	HEXES
%token	STRING
%token	BOOL
%token	DEFSYM
%token	DIRECTIVE
%token	VARNAME
%token	SEMICOLON
%token	COLON
%token	COMMA

%%

root : list { 
		DebugMessage("YACC -> \t\t* Root Found \n");
		DebugMessage("YACC -> \t\t* Lex and YACC parses garuda rules succesfuly\n");
		success_flg = 1 ;
}
;

list: statement | statement list {
		DebugMessage("YACC -> \t\t* List Found \n");

}
;


statement: ACTION expr SEMICOLON {
		DebugMessage("YACC -> \t\t* Statement Found\n");
		rtype_id = GetActionType( (char*)$1 ) ;
		if ( rtype_id < 0 )
			perror("action not found");

		rule[r_order].d_type = rtype_id ;
		rule[r_order].chklist[chkid] = -1 ;
		/*
		res =  fwrite( &rule[r_order], sizeof(Rule_Entry), 1, fp );
		if ( res != 1 )
			perror("rule insert");
		*/

		r_order++;
		chkid = 0 ;
	} 
;

expr: 	fieldset | fieldset COMMA expr  {
		DebugMessage("YACC -> \t\t* Expression Found\n");
	}
;

fieldset: VARNAME COLON value { 
	/* search VARNAME from lex symbol table
	 * construct wireless header in map
	 */
		DebugMessage("YACC -> \t\t* Fieldset Found\n");
		DebugMessage("YACC -> \t\t Variable: $1=%s,type=%d,$3=%s,var_type=%d\n", (char*)$1, GetFieldID((char*)$1), $3, var_type );
		set_var( r_order, GetFieldID((char*)$1) , (char*)$3, var_type );

	}
;

value:	HEX1 | HEX2 | HEX3 | HEX4 | HEXES | STRING | BOOL | DEFSYM | DIRECTIVE  
;


%%


int GetActionType( char *actstr ) 
{
	int i , res = -1;

	for ( i=0 ; i < 4 ; i++ ) {
		if ( !strcmp( rtype[i], actstr )  ) {
			res = i ;
		}
	}

	return res ;

}


/****************************************************************************
  *
  * Function : LoadRule()
  *
  * Purpose : parse rule and load data into rule[]
  *
  * Arguments : void
  *
  * Returns : 1 == success
  *          -1 == error
  *
  ***************************************************************************/
int LoadRule( void )
{

	// SysMessage("Parsing rule started");
	
	if (  InitLexInput( gConfig.RuleFilename ) < 0 ) {
		SysErrorMessage("InitLextInput() : failed  ");
		return ERROR ;
	}

	yyparse();

	if ( success_flg != 1 ) {
		SysErrorMessage("Parsing rule failed ");
		SysErrorMessage("Re-Config your rule file");
		return ERROR ;
	}

	// SysMessage("Parsing rule completly done"); 

	return TRUE;

}

