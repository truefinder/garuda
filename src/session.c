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
/* $Id: session.c,v 1.5 2004/06/25 08:40:22 seunghyun Exp $ */

/****************************************************************************
  * 
  * session.c 
  *
  * check source mac/ip , destination mac/ip in real-time
  * periodically refresh session table (add, delete, count)
  * resulty, session table information will be writed into session.log
  *
  * TODO : it have to support database system 
  *
  ***************************************************************************/

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include "cio.h"
#include "wpacket.h"
#include "wpktapi.h"
#include "type.h"
#include "session.h"
#include "config.h"
#include "chkspoof.h"
#include "mysql.h"

/*** Global Variables ***/
extern Config	gConfig ;
extern Log	gLog ;

Session gSession;



/****************************************************************************
  *
  * Description :  init session
  * init session.log and  gSession session table
  *
  * Returns : 1 == success
  *          -1 == fail 
  ***************************************************************************/
int
InitSession( void )
{
	/*
	void *shmaddr = (void*)0;
	int shmid ;

	// Shared Memory Init
	shmid = shmget( (key_t)SHMKEY_SESSION , (sizeof(WSession)) , 0777|IPC_CREAT );

	if ( shmid < 0 ) {
		//return FALSE ;
		return -1 ;
	}
	
	shmaddr = shmat ( shmid, (void*)0, 0 );
	wsp = ( WSession *) shmaddr ;
	*/

	memset( &gSession , '\0', sizeof(Session) ) ;


	// log file inialization , testing

	// mysql support
	if ( ! gConfig.mysql_use )  {
		gLog.SessionFp = fopen( gLog.SessionLog , "w" ) ; // truncate zero-length or create
		if ( gLog.SessionFp == NULL )  {
			SysErrorMessage("InitStatistics() : cannot open session.log ");
			return ERROR;
		}
	}


	return TRUE ;
}




/****************************************************************************
  *
  * Function : SearchSession( SessionEntry *)
  *
  * Purpose : search session table
  *
  * Arguments : newsess ==> new session pointer 
  *
  * Returns : 0 <= x < 1024 == found
  *           -1 == fail
  *
  ***************************************************************************/
int 
SearchSession ( SessionEntry *newsess ) 
{
	int i ;

	for ( i= 0 ; i < gSession.index ; i++ ) {
		if ( gSession.index == 0 ) 
			return -1 ;

		// gSession.src -> dst
		if ( gSession.table[i].src_ip.s_addr == newsess->src_ip.s_addr && \
			gSession.table[i].dst_ip.s_addr == newsess->dst_ip.s_addr && \
			!bcmp( gSession.table[i].src_mac, newsess->src_mac, 6 ) && \
			!bcmp( gSession.table[i].dst_mac, newsess->dst_mac, 6 ) && \
			!bcmp( gSession.table[i].bssid , newsess->bssid, 6 ) )
		{
			//found
			return i ;
		}

		// gSession.dst -> src
		if ( gSession.table[i].src_ip.s_addr == newsess->dst_ip.s_addr && \
			gSession.table[i].dst_ip.s_addr == newsess->src_ip.s_addr && \
			!bcmp( gSession.table[i].src_mac, newsess->dst_mac, 6 ) && \
			!bcmp( gSession.table[i].dst_mac, newsess->src_mac, 6 ) && \
			!bcmp( gSession.table[i].bssid , newsess->bssid, 6 ) )
		{
			//found
			return i ;
		}

	}
	return -1 ;
}



/****************************************************************************
  *
  * Function : AddSession( SessionEntry *, MacHdr * , len )
  *
  * Purpose :
  *  add new session into session table 
  *
  * Arguments : newsess ==> session pointer
  *             mp ==> packet pointer
  *             len ==> packet size
  *
  * Returns : void
  *
  ***************************************************************************/
void 
AddSession( SessionEntry *newsess,  MacHdr *mp, int len )
{

	newsess->seq = mp->sequence ;
	newsess->pkt_count = 1;
	newsess->first_time = time( &newsess->first_time );
	newsess->last_time = time( &newsess->last_time );
	gSession.table[gSession.index++] = *newsess ;

	return ;

}



/****************************************************************************
  *
  * Function : do_session()
  *
  * Purpose : 
  *  manage gSession table periodically
  *
  * Arguments : mp ==> packet header pointer 
  *             len ==> packet size 
  *
  * Returns : void
  *
  ***************************************************************************/
void 
do_session( MacHdr *mp , int len ) 
{
	int found = -1;
	struct in_addr *pIp ;
	char *macptr ;
	time_t xtime ;
	DataHdr *datahdr ;

	SessionEntry newsess ;

	if ( COOK_FRAME_TYPE(mp->frm_ctrl) != DATA_FRAME ) 
		return ;

    // if it's not a ip protocol, return 
	if ( is_unofficial_datfrm( mp ) )
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
	else {
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) - 6 )  ;
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
		}
	}

	if ( (datahdr->proto_id & 0x00ff )  != 0x0008 ) {  // IP proto 0x0008
		return  ;
	}

	memset( &newsess, '\0', sizeof( SessionEntry ));


	if ( (macptr = get_srcmac(mp))   != NULL ) 
		memcpy( newsess.src_mac, macptr, 6);

	if ( (macptr = get_dstmac(mp))   != NULL ) 
		memcpy( newsess.dst_mac, macptr, 6);

	if ( (macptr = get_bssidmac(mp)) != NULL )  
		memcpy( newsess.bssid,  macptr, 6 );

	pIp = (struct in_addr *) get_dat_srcip ( mp ) ;
	if ( pIp != NULL ) newsess.src_ip = *pIp;

	pIp = (struct in_addr *)get_dat_dstip ( mp ) ;
	if ( pIp != NULL ) newsess.dst_ip = *pIp;

	newsess.src_port = get_dat_srcport( mp) ;
	newsess.dst_port = get_dat_dstport( mp) ;

	
	/* case of new session */
	if ( (found = SearchSession(&newsess)) < 0  ) {

		AddSession( &newsess, mp, len );

	/* case of exist session */
	} else  if ( found >= 0 ) {
		/* update session */
		gSession.table[found].pkt_count++;
		gSession.table[found].last_time = time( &xtime );

		/* checkspoof !!!! here 
		   if spoofing found , LogDetect() called 
		 */
		CheckSpoof( mp, found );

		return ;
	}

	if ( gSession.index > MAX_SESSION -1 ) {
		gSession.index = 0;
		memset( &gSession ,'\0', sizeof( Session) );

	}

	return ;
}



/****************************************************************************
  *
  * Function : LogSession ()
  *
  * Purpose : log session in the session.log
  * loging stuffs are 
  *  first time , last time, packet count, total size, 
  *  src mac , dst mac, bssid, src ip, src port, dst ip, dst port
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/
void 
LogSession( void ) 
{
	extern char *tzname[2];
	extern long timezone;
	extern int daylight ;
	char ftime[32] ;
	char ltime[32] ;

	char src_mac[32];
	char dst_mac[32]; 
	char bssid_mac[32]; 
	char srcip[32];
	char dstip[32];

	int i ; 
	char * sqlQuery, *sqlQuery2 ;

	tzset();

	// mysql support
	if ( gConfig.mysql_use ) {
		sqlQuery2 = (char*) strdup( "DELETE from session");
		LogIntoMysql( sqlQuery2 );
		free( sqlQuery2 );
	} else {
		fclose( gLog.SessionFp );
		gLog.SessionFp = fopen( gLog.SessionLog , "w" );
	}

	for ( i =0; i< gSession.index ; i++ ) {

		memset( ftime, '\0', sizeof(ftime) );
		strftime( ftime, sizeof(ltime), "%F %T", localtime(&gSession.table[i].first_time) );

		memset( ltime, '\0', sizeof(ltime) );
		strftime( ltime, sizeof(ltime), "%F %T", localtime(&gSession.table[i].last_time) );

		wnet_mtos ( src_mac , gSession.table[i].src_mac );
		wnet_mtos ( dst_mac , gSession.table[i].dst_mac );
		wnet_mtos ( bssid_mac , gSession.table[i].bssid );

		memset( srcip, '\0', sizeof(srcip) );
		sprintf( srcip, "%s", (char*)inet_ntoa( gSession.table[i].src_ip)  );

		memset( dstip, '\0', sizeof(dstip) );
		sprintf( dstip, "%s", (char*)inet_ntoa( gSession.table[i].dst_ip)  );

		if ( gConfig.mysql_use ) {
			// mysql support 
			sqlQuery = (char *)calloc( 1, 1024 ) ;
			sprintf( sqlQuery , \
				"INSERT INTO session VALUES \
				( '', '%s', '%s', %d, %d, '%s', '%s', '%s', '%s', %d, '%s', %d )", \
				ftime, ltime, gSession.table[i].pkt_count , gSession.table[i].tot_size , \
				src_mac, dst_mac, bssid_mac, \
				srcip, ntohs(gSession.table[i].src_port), \
				dstip, ntohs(gSession.table[i].dst_port) );
			LogIntoMysql( sqlQuery );

			free(sqlQuery );


		} else { // file log 

			fprintf( gLog.SessionFp, "%s %s %d %d %s %s %s %s %d %s %d\n", \
				ftime, \
				ltime, \
				gSession.table[i].pkt_count , \
				gSession.table[i].tot_size , \
				src_mac, \
				dst_mac, \
				bssid_mac, \
				srcip, ntohs(gSession.table[i].src_port), \
				dstip, ntohs(gSession.table[i].dst_port) \
			);

			fflush( gLog.SessionFp );
		}
	}


	return ;
}

