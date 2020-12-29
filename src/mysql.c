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
/* $Id: mysql.c,v 1.1 2004/06/23 09:14:18 seunghyun Exp $ */

/****************************************************************************
  * mysql.c
  *
  * it supports to get log entries into mysql database
  *
  ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include "type.h"
#include "config.h"
#include "garuda.h"
#include "rule.h"
#include "mysql.h"
#include "cio.h"


/* global variables */
extern Config gConfig ;
extern MYSQL mysql; 

/* local variables */

/* local functions */
/****************************************************************************
  *
  * Function : InitMysql ()
  *
  * Purpose : initialization for mysql support
  *
  * Arguments : void
  *
  * Returns : -1 when error ocurr, 
  * 		when it success 1 return
  *
  ***************************************************************************/
int InitMysql ( void ) 
{
	if (!(mysql_connect(&mysql, gConfig.MysqlHost, gConfig.MysqlUser,gConfig.MysqlPass)))  
	{
		SysErrorMessage( mysql_error(&mysql) );
		return ERROR ;
	}

	return TRUE ;
}


/****************************************************************************
  *
  * Function : LogIntoMysql ( char *)
  *
  * Purpose : log into database
  *
  * Arguments : sqlQuery ==> sql query string
  *
  * Returns : -1 when error ocurr, 
  * 		when it success 1 return
  *
  ***************************************************************************/
int LogIntoMysql ( char *sqlQuery )
{ 
	/*
	MYSQL_RES *res; 
	MYSQL_ROW row;
	*/

	/*
	if (!(mysql_connect(&mysql,"localhost","devel","elqlroot"))) 
	    //error
	    */

	if (mysql_select_db(&mysql,DBNAME )) {
		SysErrorMessage(mysql_error(&mysql)); 
		return ERROR ;
	}

	if (mysql_query(&mysql, sqlQuery)) {
		SysErrorMessage(mysql_error(&mysql));
		return ERROR ;
	}


	return TRUE;
}



