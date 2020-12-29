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
/* $Id: chkspoof.c,v 1.2 2004/06/18 09:27:39 seunghyun Exp $ */
/*********************************************************************
  *
  * chkspoof.c
  *
  * it searches something spoofed mac address, tracking sequence number 
  * of wireless users
  * it's based on research of Johua.Wright@jwu.edu
  * "Detecting Wireless LAN MAC Address Spoofing"
  * 
  * TODO:
  *	it have to get experienced about 'expectable range' 
  *     in various cases 
  ********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include "wpacket.h"
#include "wpktapi.h"
#include "rule.h"
#include "garuda.h"
#include "session.h"
#include "member.h"
#include "detect.h"
#include "chkspoof.h"

/*** global variables ***/
extern Session gSession ;
extern Rule_Entry rule_internal[MAX_RULE_INTERNAL] ;


/****************************************************************************
  *
  * Function : CheckSpoof( MacHdr *, int )
  *
  * Purpose : check new session if it's sequence is in expectable range
  *
  * Arguments : mp ==> packet pointer
  *             found ==> found 
  *
  * Returns : void
  *
  ***************************************************************************/

#define ER_LEVEL1	1
#define ER_LEVEL2	2
#define ER_LEVEL3	3
#define ER_LEVEL4	4
#define ER_LEVEL5	5


void 
CheckSpoof( MacHdr *mp , int found )
{
	int nDiff ;
	time_t curtime ;
	unsigned int seconds ;
	struct in_addr *pIp;
	char mac1[32] ;
	int caseid ;

	rule_internal[IRN_MACSPOOF].id = IRN_MACSPOOF ;
	rule_internal[IRN_MACSPOOF].d_type = 0 ;
	rule_internal[IRN_MACSPOOF].count = 0 ;
	rule_internal[IRN_MACSPOOF].timer = 0;
	rule_internal[IRN_MACSPOOF].risk = 4 ;
	sprintf( rule_internal[IRN_MACSPOOF].desc , "%s", \
		"Mac Spoofing Found !!! " );

	/* Expectable Range 
	   * 
	   * Definitaion : 
	   *  mac spoofing could be occured by attacker when he changes his mac address
	   *  it features  that sequence number get difference of it
	   *  for example sequence number dumped 167, 168, 169, 2029, 2030, 2031 ...
	   *  attacker attend to network sequence 2029
	   *  garuda could not cover all of wireless packets in real-filed
	   *  so we have to make a definition 'Expectable Range'
	   * 
	   *  1. ignore under 100 difference
	   *  2. if over 100 diffence occured, decide by expiration time 
	   *   .1 500  : ignore under 10 min
	   *   .2 1000 : ignore under 30 min
	   *   .3 5000 : ignore under 2 hours
	   *   .4 over 5000 : all detection
	   *
	   */
	tzset();
	curtime = time( &curtime);
	memset( mac1, '\0', sizeof(mac1) );

	nDiff = abs( (int)( mp->sequence - gSession.table[found].seq) ) ;
	seconds = abs ( (int)curtime - gSession.table[found].last_time );

	wnet_mtos ( mac1 , gSession.table[found].src_mac );
	pIp = get_dat_srcip( mp ) ;


	caseid = nDiff >= 5000 ? ER_LEVEL5 : 
		( nDiff >= 1000 ? ER_LEVEL4 : 
		  ( nDiff >=  500 ? ER_LEVEL3 : 
		    ( nDiff >=  100 ? ER_LEVEL2 : ER_LEVEL1 
		    ) 
		  )
		) ;

	snprintf( rule_internal[IRN_MACSPOOF].desc,  sizeof(rule_internal[IRN_MACSPOOF].desc) , \
		"%s ( %s %s seq_diff=%d)", "Mac spoofing found ", mac1, pIp == NULL ? "no ip": inet_ntoa(*pIp), nDiff);

	switch ( caseid ) 
	{
		case ER_LEVEL1:
			// ignore under 100 sequence difference
			break;

		case ER_LEVEL2:
			if ( seconds < 60*10 )  break;
			else LogDetect( mp, &rule_internal[IRN_MACSPOOF] );

			break;

		case ER_LEVEL3:
			if ( seconds < 60*30 ) break;
			else LogDetect( mp, &rule_internal[IRN_MACSPOOF] );

			break;

		case ER_LEVEL4:
			if ( seconds < 60*60*2) break;
			else LogDetect( mp, &rule_internal[IRN_MACSPOOF] );

			break;

		case ER_LEVEL5:
			if ( seconds < 60*60*6) break;
			else LogDetect( mp, &rule_internal[IRN_MACSPOOF] );

			break;

		default :
			break;
	}

	return ;
}


/****************************************************************************
  *
  * Function : SearchSpoofedMac( struct in_addr , char * )
  *
  * Purpose : 
  *  search session mac,ip with variables search_ip and search_mac in member list
  *  if these (both search_mac and search_ip) are same with src_mac and src_ip 
  *  of gSession entry, continue .
  *  but return entry number ;
  *
  * Arguments : search_ip  ==> member's ip
  *           : search_mac ==> member's mac
  *
  * Returns : x => 0 == if found 
  *               -1 == nothing
  *
  ***************************************************************************/
/*** 
int 
SearchSpoofedMac( struct in_addr search_ip, char *search_mac ) 
{
	int i ;

	for ( i =0 ; i< gSession.index ; i++ ) {
		if ( gSession.table[i].src_ip.s_addr  == search_ip.s_addr  ){
			if ( ! memcmp( gSession.table[i].src_mac , search_mac , 6 ) )
				continue ;
			else
				return i ; // found spoofed mac !!! 
		}
	}

	return -1 ;
	
}
****/


/****************************************************************************
  *
  * Function : CheckSpoof()
  *
  * Purpose :
  * check member list and session table for finding spoofed mac address
  * do_period()  calls CheckSpoof() periodically
  * it compares between client's session ip in gSession.table and 
  * member mac address in gMember list
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/
/***
void CheckSpoof(void ) 
{
	int i ;
	Member *pMember ;
	int found = -1;

	char mac1[32];
	char mac2[32];


	// setting output description 
	MacSpoofRule.id = 0 ;
	MacSpoofRule.d_type = 0 ;
	MacSpoofRule.count = 0 ;
	MacSpoofRule.timer = 0;
	MacSpoofRule.risk = 4 ;

	// setting null mac header 
	memset( &NullMachdr , '\0', sizeof( MacHdr ) );

	pMember = gMemberHead.next ;

	for ( i=0 ; i < gMemberHead.total ; i++ ) 
	{

		// if member has real ip 
		if (  pMember->type == MEMBERTYPE_STATION && pMember->ip.s_addr ) 
		{
			// search session table 
			found = SearchSpoofedMac ( pMember->ip, pMember->mac  )  ;

			// if spoofed mac session found, call LogDetect() 
			if ( found >= 0 )  
			{
				wnet_mtos ( mac2, pMember->mac );
				wnet_mtos ( mac1 , gSession.table[found].src_mac );

				snprintf( MacSpoofRule.desc,  sizeof(MacSpoofRule.desc) , \
					"%s %s %s %s", "Mac spoofing found : ", \
					inet_ntoa(pMember->ip),  \
					mac1 , \
					mac2 );

				LogDetect( &NullMachdr, &MacSpoofRule );
			}
		}

		pMember = pMember->next ;
	}

	return ;		
}
***/

