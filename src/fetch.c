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
/* $Id: fetch.c,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */

/****************************************************************************
  * fetch.c 
  *
  * caller of statistics module, session module, object enummeration module 
  * and filter module. various functions and modules could be added here
  *
  ***************************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <sys/utsname.h>
#include <pcap.h>
#include <asm/types.h>
#include "garuda.h"
#include "cio.h"
#include "fetch.h"
#include "type.h"
#include "wpacket.h"
#include "chkfrm.h"
#include "log.h"
#include "session.h"
#include "statistics.h"
#include "rule.h"
#include "config.h"
#include "detect.h"
#include "member.h"
#include "filter.h"

/*** Global variables ***/
extern Rule_Entry rule[MAX_RULE];
extern Config gConfig ;


/****************************************************************************
  *
  * Function : FetchWlanPacket()
  *
  * Purpose : main caller of various routines
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/
void 
FetchWlanPacket ( const u_char *pkt_data, int len )
{ 
	PrismHdr *prismhdr ;
	MacHdr *machdr ; 
	struct timespec tmspc ;

#ifdef	PRISM
	prismhdr = (PrismHdr *) pkt_data ;
	machdr = ( MacHdr *) ( pkt_data + sizeof(PrismHdr) );
#else
	machdr = ( MacHdr *)( pkt_data );
	prismhdr = NULL ;
#endif

	// statistics processing
	do_statistics( (char*)machdr, len );

	// session processing 
	do_session( (MacHdr  *)machdr, len );

	// do_member treats wireless objects's list and detects null assoc, null probe
	do_member( (MacHdr *)machdr, len );

	// if it runs on offline mode,  time interval added
	if ( gConfig.off ) {
		tmspc.tv_nsec = OFFLINE_NANOSLEEP  ;
		tmspc.tv_sec = 0 ;
		nanosleep(&tmspc, NULL);
	}

	// if it runs on console mode print "."
	if ( !gConfig.mode_deamon ) 
		write( 1, ".", 1 );


#ifdef	PRISM
	do_detect( (MacHdr *)machdr, len - sizeof(PrismHdr) ) ;
#else 
	do_detect( (MacHdr *)machdr, len );
#endif


	//  user filter blocks packet logging
	if (  ! MatchFilter(machdr->frm_ctrl) ) {
		return ;
	}
	/* SavePacket( machdr, len ) */

	return ;
}


