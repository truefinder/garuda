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
/* $Id: log.c,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */

/****************************************************************************
  *
  * log.c
  *
  * it manages detect.log session.log statistics.log session.log 
  *
  *
  ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "wpacket.h"
#include "fetch.h"
#include "chkfrm.h"
#include "log.h"
#include "wpktapi.h"
#include "config.h"
#include "statistics.h"
#include "member.h"
#include "session.h"
#include "chkspoof.h"


/*** Global variables ***/
extern Config gConfig ;
extern Log	gLog ;




/****************************************************************************
  *
  * Function : do_period( int )
  *
  * Purpose : 
  *  it logs sessin table, statistics and member list , also
  *  checks if attacker spoofs the mac
  *
  * Arguments : sig ==> formal argument
  *
  * Returns : void
  *
  ***************************************************************************/
void do_period (int sig) 
{
	// periodically called by timer and call below functions
	LogSession();
	LogStatistics() ;
	LogMember();
	// dummy()

	if ( !gConfig.mode_deamon )
		write(1, "*", 1 );
	
	return ;
}


// if it need to log each packet, we can make code here. 
void 
SaveWPacket( MacHdr *mp, int len )
{

	return ;
}



