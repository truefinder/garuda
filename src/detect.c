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
/* $Id: detect.c,v 1.2 2004/06/23 09:14:18 seunghyun Exp $ */

/****************************************************************************
  *
  * detect.c 
  *
  * processing rule instruction "match", "count", "status"
  * case of "match"  if MatchAll() returns TRUE , 
  * it will write detection description into detect.log
  * case of "count" garuda uses gSuspect table to judge if it's DoS attack
  * case of "status" not implemented
  *
  * TODO:
  * "status" module implemented
  *
  *
  ***************************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <sys/utsname.h>
#include <asm/types.h>
#include <fcntl.h>
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
#include "wpktapi.h"
#include "mysql.h"

/*** Global variables ***/
extern Config gConfig ;
extern Log	gLog ;
extern Rule_Entry rule[MAX_RULE];
extern int (* check_frm[MAX_CHECKER])(MacHdr *mp, Rule_Entry *rp, int n) ;

Suspect	gSuspect ;


/*** Internal fuctions ***/
void Detect ( MacHdr *mp , Rule_Entry *rp , int len );
int JudgeIfDoS ( MacHdr *mp,  Rule_Entry *rp ) ;
void RefreshSuspectTable(void) ;
void InsertSuspectEntry( int i, char *srcmac , Rule_Entry * rp );
int  SearchSuspectTable ( int id , char *srcmac ); 
void TrackingStatus( MacHdr *mp , Rule_Entry *rp );




/****************************************************************************
  *
  * Description :
  * the suspect table is a kind of map for judging if new packet is one of DoS attack
  *
  ***************************************************************************/
void InitSuspectTable( void ) 
{
	memset( &gSuspect, '\0', sizeof( Suspect) );

	return  ;
}


/****************************************************************************
  *
  * Function : InitDetect()
  *
  * Purpose : init suspect table and open and create detect.log
  *
  * Arguments : void
  *
  * Returns : 1 == success
  *          -1 == fail
  *
  ***************************************************************************/
int InitDetect( void )
{
	InitSuspectTable();

	// mysql support
	if ( !gConfig.mysql_use )  {
		gLog.DetectFd=open( gLog.DetectLog ,O_RDWR|O_CREAT|O_APPEND , \
			S_IRUSR|S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );

		if ( gLog.DetectFd < 0 )
			return ERROR ;
	}

	return TRUE ;

}



void 
LogDetect( MacHdr *mp, Rule_Entry *rp )
{
	extern char *tzname[2];
	extern long timezone;
	extern int daylight ;

	int res ;
	time_t ts ;
	struct utsname name ;
	char hostnm[32] ;
	char ltime[32] ;
	char src_mac[32], dst_mac[32], bssid_mac[32]; 
	char ssid[32];
	char *log_buffer;
	char *macptr ;
	char *sqlQuery; 
	
	// msg 
	/*
	RtMsg rtmsg ;
	key_t ukey ;
	int msgq_id ;
	*/


	sprintf( src_mac, "00:00:00:00:00:00" );
	sprintf( dst_mac, "00:00:00:00:00:00" );
	sprintf( bssid_mac, "00:00:00:00:00:00" );


	sprintf( ssid, "	");
	if ( (macptr = get_srcmac(mp)) != NULL );
		wnet_mtos ( src_mac , macptr );

	if ( (macptr = get_dstmac(mp)) != NULL );
		wnet_mtos ( dst_mac, macptr );

	if ( (macptr = get_bssidmac(mp)) != NULL );
		wnet_mtos ( bssid_mac, macptr );

	res = time( &ts );
	res = uname ( &name );
	tzset();

	memset( ltime, '\0', sizeof(ltime) );
	strftime( ltime, sizeof(ltime), "%F %T", localtime(&ts) );


	res = gethostname( hostnm , sizeof(hostnm) );
	if ( res < 0  )
		strcpy( hostnm , "unkown" );


	/* log format 
	 * time | host name | alert type | attack id | src mac | dst mac | bssid | description 
	 */

	/*log format
	Time
   	Hostname
	Rule id
	Rule type
	Risk (High/Medium/Low)
	Src MAC
	Dst MAC
	BSSID MAC
	SSID
	Description
	*/

	// mysql support
	if (  gConfig.mysql_use ) {
		// mysql log
		sqlQuery =(char*) calloc(1, 1024 );
		sprintf ( sqlQuery, "INSERT INTO detect VALUES ( \
			'', '%s','%s','%d','%d','%d','%s','%s', '%s','%s', '%s')", \
				ltime, hostnm, rp->id, rp->d_type, rp->risk, \
				src_mac , dst_mac, bssid_mac, \
				ssid, rp->desc  \
				);

		LogIntoMysql( sqlQuery );

		free(sqlQuery );
		
	}else { // file log
		log_buffer=(char *)calloc(1,strlen(ltime)+strlen(hostnm)+10*3+strlen(src_mac)+strlen(dst_mac)+strlen(bssid_mac)+strlen(ssid)+strlen(rp->desc)+10);
		if(log_buffer) {
			sprintf(log_buffer,"%s %s %d %d %d %s %s %s %s %s\n",  \
				ltime, \
				hostnm, \
				rp->id, \
				rp->d_type, \
				rp->risk, \
				src_mac , \
				dst_mac, \
				bssid_mac, \
				ssid, \
				rp->desc  \
				);

			if(gLog.DetectFd>0) {
				write(gLog.DetectFd,log_buffer,strlen(log_buffer));
			}else{
				if ( ! gConfig.mode_deamon )
					write(1,log_buffer,strlen(log_buffer));
			}
			// if msg queue exist, write into log
			//ukey = ftok("./", 'm' );
			/*
			ukey = 1000 ;
			msgq_id = msgget( ukey, 0660 );
			if ( msgq_id > 0 ) {
				puts("m");
				rtmsg.mtype = 1L ;
				strncpy( rtmsg.mtext, log_buffer, MAX_RTMSG_SIZE );
				msgsnd ( msgq_id, (struct msgbuf*)&rtmsg, strlen( rtmsg.mtext)+1, 0 ); 
			}
			*/
		free(log_buffer);
		}
	}// file log 

}

/****************************************************************************
  *
  * Description :
  * do_detect() is caller of real Detect()
  *
  ***************************************************************************/
void 
do_detect( MacHdr *machdr, int len )
{
	int i =0;
	MacHdr *p = machdr ;

	for ( i=0 ; i< MAX_RULE ; i++ ) { 
		// every rule have unique id ,if 0 found it reaches rule end
		if ( rule[i].id == 0 ) 
			return ;

		if ( (p->frm_ctrl & FC_MASK) == (rule[i].rpkt.machdr.frm_ctrl & FC_MASK) )
			Detect( p , &rule[i], len  ) ;
	}
	return ;
}


/****************************************************************************
  *
  * Function : MatchAllField( MacHdr *, Rule_Entry *, int )
  *
  * Purpose :
  * check all field of current wireless packet between rule entry
  *
  * Arguments : mp ==> packet header pointer
  *             rp ==> rule entry pointer
  *            len ==> packet length
  *
  * Returns : 1 == every field matches
  *           0 == one of field did'nt match
  *
  ***************************************************************************/
int 
MatchAllField( MacHdr *mp , Rule_Entry *rp, int len ) 
{
	int res=0, i=0 ;


	while( 1 ) 
	{
		// normal case
		if ( rp->chklist[i] > 0 && rp->chklist[i] < MAX_CHECKER )  { 
			// if  check_frmXXXXX() failed, it returns 0
			// but else it returns unique number
			res = check_frm[rp->chklist[i]]( mp, rp, len) ;
			if ( ! res )
				return FALSE;
			i++; 
		}
		// at the end of checklist, we can found -1 
		// "founding -1" means processing have done correctly.
		else if ( rp->chklist[i] == -1 )
			break;
		// integrity false
		else
			return FALSE;
	}
	
	// if the last returned value matches checklist[i-1]
	// it means all of fields matches. we detect the attack.
	if ( res == rp->chklist[i-1] )
		return TRUE;
	else 
		return FALSE ;

}


/****************************************************************************
  *
  * Function : Detect( Mahdr *, Rule_Entry * , int)
  *
  * Purpose :
  * checks if it's an attack and writes into detection log calling LogDetect()
  *
  * Arguments : mp ==> packet header pointer
  *             rp ==> rule entry pointer
  *            len ==> packet length
  *
  * Returns : void
  *
  ***************************************************************************/
void 
Detect( MacHdr *mp, Rule_Entry *rp, int len )
{
	int res ;
	if ( ! MatchAllField( mp, rp, len )) 
		return ;

	switch ( rp->d_type ) {
		case RTYPE_MATCH: 
			/* Warn ! */
			LogDetect( mp, rp );
			break;
		case RTYPE_COUNT:
			/* DoS ? */
			res = JudgeIfDoS( mp, rp );
			if ( res > 0 ) 
				LogDetect( mp, rp );
			break;
		case RTYPE_STATUS:
			TrackingStatus(mp,rp);
			break;

		default:
			return;
	}

	return ;
}


/****************************************************************************
  *
  * Function : JudgeIfDoS( MacHdr *, Rule_Entry *)
  *
  * Purpose : 
  * judge if current wireless packet is one of the DoS packet
  *
  * Arguments : mp ==> packet header pointer
  *             rp ==> rule entry poniter
  *
  * Returns : 1 ==  DoS Found
  *           0 ==  No it's not DoS packet
  *
  ***************************************************************************/
int 
JudgeIfDoS ( MacHdr *mp,  Rule_Entry *rp )
{
	int i;   
	time_t cur_time; 
	time_t ts ;
	//struct tm *tset ;
	char dosflg = 0 ;
	char *srcmac ;

	// 1.table processing
	// search suspect table 
	srcmac = get_srcmac( mp );
	i = SearchSuspectTable( rp->id, srcmac );

	// if not found, insert suspect table
	if ( i < 0 ) {
		InsertSuspectEntry ( gSuspect.index , srcmac, rp ); 
		gSuspect.index++;

		// if suspect table reaches end of entry, force refresh
		if ( gSuspect.index > MAX_SUSPECTENTRY  ) {
			gSuspect.index=0;
			RefreshSuspectTable();
		}

		return FALSE ;

	} else {
	// if found, add count
		if ( i< MAX_SUSPECTENTRY ) {
			gSuspect.table[i].total++; 
			dosflg = 1; 
		}
	}

	//2. judging processing
	if ( dosflg ) {
		tzset();
		ts = time(&ts );
		cur_time = ts ;

		// judging DoS attack if suspect table entry count is more than 
		// rule entry count in rule entry timer
		if ( (gSuspect.table[i].start_time + rp->timer <= cur_time ) \
			&& gSuspect.table[i].total > rp->count ) 
		{
			// Detect DoS  !
			// write detection log into detect.log 
			gSuspect.table[i].disable = 1 ;
			LogDetect( mp , rp) ;
			return TRUE ;
		}
	}

	return FALSE;
}


/****************************************************************************
  *
  * Description :
  * search suspect entry from suspect table with current wlan src mac address
  * 
  * Returns : x => 0 : found
  *           -1 : not found
  *
  ***************************************************************************/
int 
SearchSuspectTable ( int id , char* srcmac ) 
{ 
	
	int i ;

	if ( gSuspect.index == 0 ) 
		return FALSE ;

	for ( i=0 ;i< gSuspect.index ; i++ ) {
		if ( (gSuspect.table[i].id==id)  && (gSuspect.table[i].disable == 0) )  
			if ( ! memcmp( srcmac, gSuspect.table[i].srcmac ,6) )  
				return i ;
	}
	return -1 ;
}


void 
RefreshSuspectTable()
{
	memset( &gSuspect, '\0', sizeof(Suspect) );
	return ;
}

void 
InsertSuspectEntry( int i, char *srcmac , Rule_Entry * rp ) 
{
	//struct tm *tset ; 
	//int seconds ;
	time_t ts ;

	tzset();
	ts = time( &ts ) ;
	/*
	tset = localtime ( &ts );
	seconds = (tset->tm_min * 60 ) + tset->tm_sec ;

	if (seconds == 0 )
		seconds = 60*60+60 ;
	*/

	gSuspect.table[i].start_time = ts ;
	gSuspect.table[i].total = 1 ;
	gSuspect.table[i].id = rp->id ;
	memcpy( gSuspect.table[i].srcmac, srcmac, 6 );

	return ;
}


/****************************************************************************
  *
  * Function : TrackingStatus( MacHdr *, Rule_Entry *)
  *
  * Purpose : session tracking and detection the attack
  *
  * Arguments : mp ==> packet header pointer
  *             rp ==> rule entry pointer
  *
  * Returns : void
  *
  * TODO : Not implemented
  *
  ***************************************************************************/
void TrackingStatus( MacHdr *mp , Rule_Entry *rp )
{
	// nothing concept, but we just get our head in the cloud
	/* if ( MatchAllStatus() ) 
		   LogDetect ( mp, rp ); 
	   */

}
