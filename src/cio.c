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
/* $Id: cio.c,v 1.1.1.1 2004/06/03 14:10:33 seunghyun Exp $ */
/****************************************************************************
  *
  * cio.c 
  * 
  * Functions for system Message
  *
  *
  ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "config.h"

extern Config	gConfig ;
extern Log	gLog ;


/****************************************************************************
  *
  * Description :  
  *
  * system initialization 
  *  void SysInitMessage( char *str ) 
  *  void SysOkMessage(void) 
  *  void SysFailMessage (void ) 
  *
  * common system message
  *  void SysMessage( char *str) 
  *  void SysErrorMessage( char *str )
  *
  * critical error occured
  *  void SysErrorExit ( char *str)
  *
  ***************************************************************************/

void SysInitMessage( char *str) 
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stdout,    "%s \t\t ... ...\t", str );
	}

	fprintf( gLog.SystemFp, "%s \t\t ... ...\t", str );
	return ;
}

void SysOkMessage(void)
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stdout, "OK\n"); fflush( stdout ); 
	}

	fprintf( gLog.SystemFp, "OK\n" ); fflush( gLog.SystemFp );

	return ;
}

void SysFailMessage (void )
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stdout, "FAIL\n"); fflush( stdout ); 
	}

	fprintf( gLog.SystemFp, "FAIL\n"); fflush( gLog.SystemFp );
}


/****************************************************************************
  *
  * Description : common system message output 
  *
  ***************************************************************************/

void SysMessage( char *str) 
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stdout, "%s\n", str ); 
		fflush( stdout ); 
	}

	fprintf( gLog.SystemFp, "%s\n", str ); 
	fflush( gLog.SystemFp );
	return ;
}



/****************************************************************************
  *
  * Description :  if fatal error occured, it will die with exit(-1) 
  *
  ***************************************************************************/

void SysErrorExit ( char *str)
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stderr, "Fatal error : %s\n",  str );
		fflush( stderr );
	}

	fprintf( gLog.SystemFp, "Fatal error : %s\n",  str );
	fflush( gLog.SystemFp );

	exit(-1) ;
}



/****************************************************************************
  *
  * Description :  general error occured, it will warn only
  *
  ***************************************************************************/

void 
SysErrorMessage( char *str )
{
	if ( ! gConfig.mode_deamon ) {
		fprintf( stdout, "Error : %s\n",  str );
		fflush( stdout );
	}

	fprintf( gLog.SystemFp, "Error : %s\n",  str );
	fflush( gLog.SystemFp );
}


void 
DebugMessage(char *fmt, ...) 
{
#ifdef DEBUGZ
	va_list ap;

	va_start(ap, fmt);
	if ( ! gConfig.mode_deamon ) {
		vfprintf(stdout, fmt, ap);
		fflush( stdout );
	}

	vfprintf(gLog.SystemFp, fmt, ap);
	fflush( gLog.SystemFp );

	va_end(ap);
#endif

	return;
}



// old io function 
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
/*
void Cout(char *str) 
{
	fprintf(stdout, "%s", str );
	return ;
}

void Coutn(char *str) 
{
	fprintf(stdout, "%s\n", str );
	return ;
}

void Cexiterr( char *str )
{
	fprintf(stderr, "ERROR: %s\n", str );
	exit(-1);
}

void Cdumphex( char *data, int len) 
{
	int i ;
	for ( i=0 ; i < len ; i++ ) {
		if ( !(i % 16) && i != 0 ) 
			printf("\n");
		printf("%02hhx ", data[i] );
	}
}

void Cdumpchar( char *data, int len) 
{
	int i ;
	for ( i=0 ; i < len ; i++ ) {
		if ( !(i % 16) && i != 0 ) 
			printf("\n");
		printf("%c ", data[i] );
	}
}


*/
