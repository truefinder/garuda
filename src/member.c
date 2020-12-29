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
/* $Id: member.c,v 1.3 2004/06/23 09:14:18 seunghyun Exp $ */

/****************************************************************************
  *
  * member.c
  *
  * this module treats wireless object infomation 
  * enumerating  ap info, associated station info
  *
  *
  ***************************************************************************/

#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "wpacket.h"
#include "wpktapi.h"
#include "member.h"
#include "config.h"
#include "garuda.h"
#include "rule.h"
#include "cio.h"
#include "detect.h"
#include "mysql.h"


/*** Galobal variables ***/
extern Config gConfig;
extern Log	gLog ;
extern Rule_Entry rule_internal[MAX_RULE_INTERNAL];

MemberHead	gMemberHead ;



/****************************************************************************
  *
  * Function : InitMember()
  *
  * Purpose : initialize member list head and open member.log
  *
  * Arguments : void
  *
  * Returns : 1 == Sucess
  *          -1 == Fail
  *
  ***************************************************************************/
int
InitMember( void )
{
	
	memset( &gMemberHead , '\0', sizeof(MemberHead) ) ;

	// mysql support
	if ( ! gConfig.mysql_use ) {

		gLog.MemberFp = fopen( gLog.MemberLog , "w" ) ; // truncate zero-length or create
		if ( gLog.MemberFp == NULL )  {
			SysErrorMessage("InitMemberList() : cannot open member.log ");
			return ERROR;
		}
		fclose( gLog.MemberFp );
		
		gLog.TrialFp = fopen( gLog.TrialLog , "w" ) ; // truncate zero-length or create
		if ( gLog.TrialFp == NULL )  {
			SysErrorMessage("InitMemberList() : cannot open trial.log ");
			return ERROR;
		}
		fclose( gLog.TrialFp );
	}
	

	return TRUE;
}

/****************************************************************************
  *
  * Description :
  * Search wireless member from the memeber list
  * compare mac address and ip at the member list
  *
  * Returns : 1 ==  found
  *           0 ==  not found
  *
  ***************************************************************************/
int
SearchMember( MacHdr *machdr, MemberHead *mhead )
{
	int i ;
	Member * pMember ;
	int res ;
	struct in_addr *ip ;

	if ( mhead->total == 0 )
		return FALSE ;

	pMember = gMemberHead.next ;
	for ( i =0 ; i < gMemberHead.total ; i++ ) 
	{
		if ( pMember == NULL || pMember == 0 ) 
			return FALSE ;

		if ( pMember->type == MEMBERTYPE_AP ) {
			res = memcmp(pMember->mac, get_srcmac( machdr), 6 );
			if ( ! res )
				return TRUE ;
			
		}
		else {
			res = memcmp(pMember->mac, get_srcmac( machdr), 6 );
			if ( ! res )
				if ( (ip = get_dat_srcip(machdr)) )
					if ( pMember->ip.s_addr == ip->s_addr ) 
						return TRUE ;
		}
		/*
		if ( ! memcmp(pMember->mac, get_srcmac( machdr), 6 ) )
			if ( ! memcmp(pMember->bssid, get_bssidmac( machdr), 6) )
				return i;  // Found !!!
		*/

		pMember = pMember->next ;
	}

	return FALSE ;
}



void
AddMember( MacHdr * machdr , int len  )
{
	Member *new ;
	time_t ts ;
	struct in_addr *srcip ;
	Mgt_Element e;
	int res ;
	

	new = calloc( sizeof( Member) , 1);
	if ( new == NULL ) {
		SysErrorMessage("AddMember() : cannot allocate memory ");
		return ;
	}
	memset( &e, '\0', sizeof(Mgt_Element) );

	tzset();
	ts = time( &ts) ;

	switch ( machdr->frm_ctrl & 0x00ff ) {
		// beacon packet is a identification of Access Point
		//
		case MGT_BEACON:
			new->id = gMemberHead.total +1 ;
			new->type = MEMBERTYPE_AP ;
			new->first_seen = ts ;

			memcpy( new->mac, get_srcmac( machdr), 6 );
			memcpy( new->bssid, get_bssidmac( machdr),  6);

			res = get_mgt_vvalue( machdr, len, EID_SSID, &e );
			if ( res ) {
				if ( e.len < sizeof(new->textssid) )
					strncpy( new->textssid, e.ptr, e.len );
				else
					strncpy( new->textssid, e.ptr, sizeof(new->textssid) );
			}
		
			res = get_mgt_vvalue( machdr, len , EID_DSPARAM, &e );
			if ( res )
				new->channel = (unsigned char)*e.ptr ;

			break;
		// data packet means session established already
		//
		case DATA:
			new->id = gMemberHead.total +1 ;
			new->type = MEMBERTYPE_STATION ;
			new->first_seen = ts ;
			memcpy( new->mac, get_srcmac( machdr), 6 );
			memcpy( new->bssid, get_bssidmac( machdr),  6);

			// we only refer a member which has ip
			if ( (srcip = get_dat_srcip(machdr)) ) 
				new->ip = *srcip ;
			else {
				free( new );
				return ;
			}
	
			break;


		default:
			free( new );
			return ;
	}
	
	gMemberHead.total++;
	new->next = gMemberHead.next ;
	gMemberHead.next = new ;

	return ; 
}


/****************************************************************************
  *
  * Function : ChkRogueAP( MacHdr, int);
  *
  * Purpose : check if it is unacceptable rogue ap
  *
  * Arguments : machdr ==> packet pointer
  *             len ==> packet length
  *
  * Returns : void
  *
  ***************************************************************************/
void ChkRogueAP( MacHdr *machdr, int len )
{
	time_t curtime ; 
	char mac1[32];
	char *srcmac ; int i ; int rogueflg = 0;


	rule_internal[IRN_ROGUEAP].id = IRN_ROGUEAP ;
	rule_internal[IRN_ROGUEAP].d_type = 0 ;
	rule_internal[IRN_ROGUEAP].count = 0 ;
	rule_internal[IRN_ROGUEAP].timer = 0 ;
	rule_internal[IRN_ROGUEAP].risk = 4 ;
	sprintf ( rule_internal[IRN_ROGUEAP].desc , "%s ", \
		"Rogue AP found !!! " );

	tzset();
	curtime = time( &curtime);
	srcmac = get_srcmac( machdr );
	wnet_mtos( mac1, srcmac );

	for ( i =0 ; i < gConfig.TrustAPNum ; i++ ) {
		if (  memcmp( &gConfig.TrustAPList.mac[i], srcmac , 6 ) ) 
			rogueflg = 1;
		else 
			return ; // it's our AP 
	}
	if ( rogueflg ) 
		LogDetect( machdr , &rule_internal[IRN_ROGUEAP] ) ;

	return ;
};

/****************************************************************************
  *
  * Description :
  *  check and manage member list in wireless network
  *
  ***************************************************************************/
void 
do_member ( MacHdr *machdr , int len )
{
	int found_id ;
	unsigned short int ptype ;

	// if probe request packet arrived, log probe info 
	ptype = machdr->frm_ctrl & 0x00ff ;
	if ( ptype == MGT_PROBE_REQ || ptype == MGT_ASSOC_REQ )
		LogTrial(machdr, len);

	// check if it is permitted Access Point
	if ( ptype == MGT_BEACON )
		ChkRogueAP( machdr, len );


	found_id = SearchMember( machdr, &gMemberHead) ;

	if ( found_id ) { // if aleady exist, return ;
		return ;
	}

	if ( gMemberHead.total < MAX_OBJECT )
		AddMember ( machdr, len  );

	return ;

}


/****************************************************************************
  *
  * Function : LogMember()
  *
  * Purpose : log member list to "member.log"
  *
  *  Items are a set of blew stuff
  * "first seen time , id, type, "ap" or "sta" , mac address, bssid address,  
  *  ip address or textssid(for AP identification) "
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/
void
LogMember( void)
{
	int i ;
	Member *pMember ;
	char src_mac[32];
	char bssid_mac[32];
	char strtime[32];
	char strip[32];
	char *sqlQuery ;
	char *sqlQuery2 ;

	

	// mysql support
	if ( gConfig.mysql_use )  {
		sqlQuery2 = (char*) strdup( "DELETE from member");
		LogIntoMysql( sqlQuery2) ;
		free(sqlQuery2);
	} else {
		gLog.MemberFp = fopen( gLog.MemberLog , "w" ) ;
		if ( gLog.MemberFp == NULL ) {
			SysErrorMessage("LogMemberList() : member file pointer is not exist ");
			return ;
		}
	}

	pMember =  gMemberHead.next ;
	for ( i = 0 ; i < gMemberHead.total ; i++ ) 
	{ 
		if ( pMember == NULL || pMember == 0 ) 
			break ;

		memset( strip , '\0', sizeof(strip) );

		wnet_mtos( src_mac, pMember->mac );
		wnet_mtos( bssid_mac, pMember->bssid );
		strftime( strtime, sizeof(strtime), "%F %T", localtime( &pMember->first_seen) ) ;
		if ( pMember->ip.s_addr ) 
			strncpy( strip, inet_ntoa( pMember->ip), sizeof(strip) );


		/**************************************************************
		 * Description: 
		 * the sequence of log entry 
		 * seen time, id, type, mac, bssid,  src ip, text ssid , channel
		 *************************************************************/

		// mysql support
		if ( gConfig.mysql_use ) 
		{
			sqlQuery = (char*) calloc( 1, 1024 );
			sprintf( sqlQuery, "INSERT INTO member VALUES ( '', '%s', %d, %d, '%s', '%s', '%s', '%s', %d )",
					strtime, pMember->id, pMember->type, src_mac, bssid_mac, \
					strip,  pMember->textssid,  pMember->channel  );
			LogIntoMysql ( sqlQuery );
			free(sqlQuery);

		} else {
		
			fprintf( gLog.MemberFp , "%s %d %d ", \
					strtime, pMember->id  , pMember->type );

			switch ( pMember->type ) {
				// if member is station
				//
				case MEMBERTYPE_STATION :
					// file log
					fprintf( gLog.MemberFp, "%s %s ", "sta", src_mac );
					if ( pMember->ip.s_addr ) {
						strncpy( strip, inet_ntoa( pMember->ip), sizeof(strip) );
						fprintf( gLog.MemberFp , "%s %s\n", bssid_mac , strip ); 
					} else {
						/*
						if ( !memcmp( pMember->bssid , "\xff\xff\xff\xff\xff\xff", 6 ) )
							fprintf( gLog.MemberFp , "%s\n", "probed or broadcasted" ); 
						else
						*/
							fprintf( gLog.MemberFp , "%s\n", bssid_mac ); 
					}

					break;

				// if member is access point
				//
				case MEMBERTYPE_AP :
					fprintf( gLog.MemberFp, "%s %s ", "ap ", src_mac );
					fprintf( gLog.MemberFp , "%s %s %d\n", bssid_mac , pMember->textssid, pMember->channel );
					break;

				default:
					fprintf( gLog.MemberFp, "\n" );
					break;
			} // switch
		}


		pMember = pMember->next ;
	}
	
	if ( ! gConfig.mysql_use )
		fclose( gLog.MemberFp );

	return ;
}


/****************************************************************************
  *
  * Function : LogTrial( Machdr *, int )
  *
  * Purpose : log probe request and assoc request info in trial.log
  * log contents are 
  *  starting time,  source mac address, packet type, ssid
  *
  * Arguments : machdr ==> wireless packet pointer
  *             len ==> packet length
  *
  * Returns : void
  *
  ***************************************************************************/
void 
LogTrial(MacHdr *machdr, int len)
{
	//Member sMember ;
	char strtime[32];
	char src_mac[32];
	char strssid[32];
	time_t ts ;
	Mgt_Element e ;
	int res ;
	unsigned short int ptype ;

	char * sqlQuery ;


	tzset();
	ts = time(&ts) ;

	// mysql support
	if ( ! gConfig.mysql_use ) {
		gLog.TrialFp = fopen( gLog.TrialLog , "a" ) ;
		if ( gLog.TrialFp == NULL ) {
			SysErrorMessage("LogTrial() : trial file pointer is not exist ");
			return ;
		}
	}

	ptype = machdr->frm_ctrl & 0x00ff ;

	memset( strssid, '\0', sizeof(strssid) );
	memset( &e, '\0', sizeof(e));
	memset( src_mac, '\0', sizeof(src_mac) );

	wnet_mtos( src_mac, get_srcmac(machdr) );
	strftime( strtime, sizeof(strtime), "%F %T", localtime( &ts ) ) ;

	res = get_mgt_vvalue( machdr, len, EID_SSID, &e );

	if ( res ) {
		// Null probe and Null assoc
		if (  e.len == 0 ) { 
			if ( ptype == MGT_PROBE_REQ ) {
				snprintf( rule_internal[IRN_NULLPROBE].desc , sizeof(rule_internal[IRN_NULLPROBE]), \
						"%s %s", src_mac, "Null Probe request found" );

				// null probe detected
				LogDetect( machdr, &rule_internal[IRN_NULLPROBE] ); 

			} else {
				snprintf( rule_internal[IRN_NULLPROBE].desc , sizeof(rule_internal[IRN_NULLPROBE]), \
						"%s %s", src_mac, "Null Assoc request found" );

				// null assoc detected
				LogDetect( machdr, &rule_internal[IRN_NULLASSOC] );
			}

			snprintf( strssid, sizeof( strssid), "%s", "Null Trial !!!");
		}
		// there are fixed ssid
		else
			snprintf( strssid,  sizeof(strssid) < e.len ? sizeof(strssid) : e.len , "%s",  e.ptr );
	}else
		;


	// mysql support
	if ( gConfig.mysql_use ) {
		//mysql log
		sqlQuery = (char*) calloc(1, 1024 ) ;
		sprintf( sqlQuery , "INSERT INTO trial VALUES \
				( '', '%s', '%s', '%s', '%s' )", \
				strtime, src_mac, 
				ptype==MGT_PROBE_REQ? "probe" : "assoc", strssid );

		LogIntoMysql ( sqlQuery );
		free(sqlQuery );

	}else {
		//file log
		fprintf( gLog.TrialFp, "%s %s %s %s\n", strtime, src_mac, \
				ptype == MGT_PROBE_REQ ? "probe" : "assoc" , strssid );
		fclose( gLog.TrialFp );
	}

	return ;
}


