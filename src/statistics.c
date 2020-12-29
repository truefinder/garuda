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
/* $Id: statistics.c,v 1.3 2004/06/23 10:08:05 seunghyun Exp $ */

/****************************************************************************
  *
  * statistics.c 
  *
  * record/count pakcet types int gStatistics 
  *
  * TODO: 
  * we have to support tcp/ip packet statistics 
  * support various protocol, ip account, traffics
  *
  *
  ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "type.h"
#include "wpacket.h"
#include "cio.h"
#include "statistics.h"
#include "config.h"
#include "mysql.h"

/*** Global variables ***/
extern Config	gConfig ;
extern Log	gLog ;

Statistics	gStatistics ;


/****************************************************************************
  *
  * Description : init statistics
  *
  * Returns : 1 == success
  *          -1 == fail
  ***************************************************************************/
int 
InitStatistics( void )
{
	/* 1. Directory statistics  */ 
	/* 
	extern char *tzname[2];
	extern long timezone ;
	extern int daylight ;

	time_t ts ;
	int res ;
	char ltime[32] ;
	struct stat buf ;
	char statistic_dir[64] ;

	res = time( &ts );
	tzset();

	memset( ltime, '\0', sizeof(ltime) );
	strftime( ltime, sizeof(ltime), "%F", localtime(&ts) );

	sprintf( statistic_dir, "statistic/%s", ltime );

	if ( stat(statistic_dir, &buf ) < 0  ) {
		mkdir( statistic_dir , 0755  );
	}
	*/


	/* 2. Global memory statistics */ 
	/* 
	   memset( &tstatus, '\0', sizeof(tstatus ) );	
	*/



	/* 3. IPC memory statistics */
	/*
	void *shmaddr = (void*) 0 ;
	int shmid ;

	shmid = shmget ( (key_t)SHMKEY_STATISTICS, sizeof( Total_Status ), 0777|IPC_CREAT );
	if ( shmid < 0 ) {
		// couldn't get shared memory from system
		return FALSE ;
	}
	shmaddr = shmat( shmid, (void*)0, 0 );
	tsp = (Total_Status *) shmaddr ;
	*/
	memset( &gStatistics, '\0', sizeof( Statistics ) );

	
	// test log file inialization
	if ( !gConfig.mysql_use ) {
		gLog.StatisticsFp = fopen( gLog.StatisticsLog , "w" ) ; 
		// truncate zero-length or create
		if ( gLog.StatisticsFp == NULL )  {
			SysErrorMessage("InitStatistics() : cannot open statistics.log ");
			return ERROR;
		}
	}

	return TRUE ;
}



void 
do_statistics( char *p, int n )
{

	/****************************************************************************
	  *
	  * Description :
	  * 1. Directory Statistics 
	  *
	  ***************************************************************************/
	/*
	 
	extern char *tzname[2];
	extern long timezone ;
	extern int daylight ;

	time_t ts ;
	int res ;
	char ltime[32] , ltime2[32];
	struct stat buf ;
	char statistic_dir[64] ;
	char statistic_filename[128];
	FILE *fp ;
	MacHdr *mhdr ;
	char line[128];

	mhdr = (MacHdr *)p ;
	res = time( &ts );
	tzset();

	memset( ltime, '\0', sizeof(ltime) );
	strftime( ltime, sizeof(ltime), "%F", localtime(&ts) );
	strftime( ltime2, sizeof(ltime2), "%F %T", localtime(&ts) );

	sprintf( statistic_dir, "statistic/%s", ltime );

	if ( stat(statistic_dir, &buf ) < 0  ) { 
		mkdir( statistic_dir , 0755  );
	}
	sprintf( statistic_filename, "%s/day.stuff", statistic_dir );

	fp = fopen( statistic_filename, "a+" );
	if ( fp == NULL )  {
		SYSERR("statistic couldnt log, so suck", -1 );
	}

	snprintf( line, sizeof(line), "%s, %04x, %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", \
			ltime2,
			mhdr->frm_ctrl, \
			mhdr->addr1[0], mhdr->addr1[1], mhdr->addr1[2], \
			mhdr->addr1[3], mhdr->addr1[4], mhdr->addr1[5] );

	fwrite( line, strlen(line), 1, fp );
	fclose(fp );
	*/


	/****************************************************************************
	  *
	  * Description :
	  * 2. Total_Status tstatus, global variable 
	  *
	  ***************************************************************************/
	/*
	extern char *tzname[2];
	extern long timezone ;
	extern int daylight ;

	MacHdr *mhdr ;
	time_t ts ;
	int res ;

	mhdr = ( MacHdr *) p ;

	if ( tstatus.ts == 0 )  {
		res = time( &ts ) ;
		tzset ();
		tstatus.ts = ts ;
	}

	switch ( mhdr->frm_ctrl & 0x00ff ) {
		case MGT_ASSOC_REQ        :
			tstatus.wstatus.mgt_assoc_req++;
			break;
		case MGT_ASSOC_RESP       :
			tstatus.wstatus.mgt_assoc_resp++;
			break;
		case MGT_REASSOC_REQ      :
			tstatus.wstatus.mgt_reassoc_req++;
			break;
		case MGT_REASSOC_RESP     :
			tstatus.wstatus.mgt_reassoc_resp++;
			break;
		case MGT_PROBE_REQ        :
			tstatus.wstatus.mgt_probe_req++;
			break;
		case MGT_PROBE_RESP       :
			tstatus.wstatus.mgt_probe_resp++ ;
			break;
		case MGT_BEACON           :
			tstatus.wstatus.mgt_beacon++;
			break;
		case MGT_ATIM             :
			tstatus.wstatus.mgt_atim++;
			break;
		case MGT_DISASS           :
			tstatus.wstatus.mgt_disass++;
			break;
		case MGT_AUTHENTICATION   :
			tstatus.wstatus.mgt_authentication++;
			break;
		case MGT_DEAUTHENTICATION :
			tstatus.wstatus.mgt_deauthentication++;
			break;
		case CTRL_PS_POLL         :
			tstatus.wstatus.ctrl_ps_poll++ ;
			break;
		case CTRL_RTS             :
			tstatus.wstatus.ctrl_rts++ ;
			break;
		case CTRL_CTS             :
			tstatus.wstatus.ctrl_cts++ ;
			break;
		case CTRL_ACKNOWLEDGEMENT :
			tstatus.wstatus.ctrl_acknowledgement++ ;
			break;
		case CTRL_CFP_END         :
			tstatus.wstatus.ctrl_cfp_end++ ;
			break;
		case CTRL_CFP_ENDACK      :
			tstatus.wstatus.ctrl_cfp_endack++;
			break;
		case DATA                 :
			tstatus.wstatus.data++;
			break;
		case DATA_CF_ACK          :
			tstatus.wstatus.data_cf_ack++;
			break;
		case DATA_CF_POLL         :
			tstatus.wstatus.data_cf_poll++;
			break;
		case DATA_CF_ACK_POLL     :
			tstatus.wstatus.data_cf_ack_poll++;
			break;
		case DATA_NULL_FUNCTION   :
			tstatus.wstatus.data_null_function++;
			break;
		case DATA_CF_ACK_NOD      :
			tstatus.wstatus.data_cf_ack_nod++;
			break;
		case DATA_CF_POLL_NOD     :
			tstatus.wstatus.data_cf_poll_nod++;
			break;
		case DATA_CF_ACK_POLL_NOD :
			tstatus.wstatus.data_cf_ack_poll_nod++;
			break;
		default:
			break;
	}
	// debug
	//printf("beacon =%d,  data = %d\n", tstatus.wstatus.mgt_beacon, tstatus.wstatus.data );
	//fflush(stdout);
	*/


	/****************************************************************************
	  *
	  * Description :
	  * now it count only wireless packet type (Mac type)
	  *
	  ***************************************************************************/
	extern char *tzname[2];
	extern long timezone ;
	extern int daylight ;

	MacHdr *mhdr ;
	time_t ts ;
	int res ;

	mhdr = ( MacHdr *) p ;

	if ( gStatistics.starttime == 0 )  {
		res = time( &ts ) ;
		tzset ();
		gStatistics.starttime = ts ;
	}

	switch ( mhdr->frm_ctrl & 0x00ff ) {
		case MGT_ASSOC_REQ        :
		    gStatistics.mac.mgt_assoc_req++;
		    break;
		case MGT_ASSOC_RESP       :
		    gStatistics.mac.mgt_assoc_resp++;
		    break;
		case MGT_REASSOC_REQ      :
		    gStatistics.mac.mgt_reassoc_req++;
		    break;
		case MGT_REASSOC_RESP     :
		    gStatistics.mac.mgt_reassoc_resp++;
		    break;
		case MGT_PROBE_REQ        :
		    gStatistics.mac.mgt_probe_req++;
		    break;
		case MGT_PROBE_RESP       :
		    gStatistics.mac.mgt_probe_resp++ ;
		    break;
		case MGT_BEACON           :
		    gStatistics.mac.mgt_beacon++;
		    break;
		case MGT_ATIM             :
		    gStatistics.mac.mgt_atim++;
		    break;
		case MGT_DISASS           :
		    gStatistics.mac.mgt_disass++;
		    break;
		case MGT_AUTHENTICATION   :
		    gStatistics.mac.mgt_authentication++;
		    break;
		case MGT_DEAUTHENTICATION :
		    gStatistics.mac.mgt_deauthentication++;
		    break;
		case CTRL_PS_POLL         :
		    gStatistics.mac.ctrl_ps_poll++ ;
		    break;
		case CTRL_RTS             :
		    gStatistics.mac.ctrl_rts++ ;
		    break;
		case CTRL_CTS             :
		    gStatistics.mac.ctrl_cts++ ;
		    break;
		case CTRL_ACKNOWLEDGEMENT :
		    gStatistics.mac.ctrl_acknowledgement++ ;
		    break;
		case CTRL_CFP_END         :
		    gStatistics.mac.ctrl_cfp_end++ ;
		    break;
		case CTRL_CFP_ENDACK      :
		    gStatistics.mac.ctrl_cfp_endack++;
		    break;
		case DATA                 :
		    gStatistics.mac.data++;
		    break;
		case DATA_CF_ACK          :
		    gStatistics.mac.data_cf_ack++;
		    break;
		case DATA_CF_POLL         :
		    gStatistics.mac.data_cf_poll++;
		    break;
		case DATA_CF_ACK_POLL     :
		    gStatistics.mac.data_cf_ack_poll++;
		    break;
		case DATA_NULL_FUNCTION   :
		    gStatistics.mac.data_null_function++;
		    break;
		case DATA_CF_ACK_NOD      :
		    gStatistics.mac.data_cf_ack_nod++;
		    break;
		case DATA_CF_POLL_NOD     :
		    gStatistics.mac.data_cf_poll_nod++;
		    break;
		case DATA_CF_ACK_POLL_NOD :
		    gStatistics.mac.data_cf_ack_poll_nod++;
		    break;
		default:
		    break;
	}

	return ;
}



void 
LogStatistics(void )
{
	char *sqlQuery ;
	char ltime[64];
	int res ;
	time_t ts ;
	/*
	void *shmaddr = (void*) 0 ;
	int shmid ;
	Total_Status *tsp ;

	shmid = shmget ( (key_t)SHMKEY_STATISTICS, sizeof( Total_Status ), 0664 );
	if ( shmid < 0 ) {
		// couldn't get shared memory from system
		fprintf( stderr, "error : shmget failed \n" );
		exit(-1);
	}
	
	shmaddr = shmat( shmid, (void*)0, 0 );
	tsp = (Total_Status *) shmaddr ;
	*/
	res = time( &ts );
	tzset();

	memset( ltime, '\0', sizeof(ltime) );
	strftime( ltime, sizeof(ltime), "%F %T", localtime(&ts) );


	if ( gConfig.mysql_use ) {
		// mysql log 
		sqlQuery = (char*) calloc( 1, 1024 );
		sprintf( sqlQuery , "INSERT INTO statistics VALUES \
			('', '%s', \
			 %d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d, \
			 %d,%d,%d,%d,%d,%d, \
			 %d,%d,%d,%d,%d,%d,%d,%d )", \
			ltime,
			gStatistics.mac.mgt_assoc_req , \
			gStatistics.mac.mgt_assoc_resp, \
			gStatistics.mac.mgt_reassoc_req, \
			gStatistics.mac.mgt_reassoc_resp, \
			gStatistics.mac.mgt_probe_req, \
			gStatistics.mac.mgt_probe_resp, \
			gStatistics.mac.mgt_beacon, \
			gStatistics.mac.mgt_atim, \
			gStatistics.mac.mgt_disass, \
			gStatistics.mac.mgt_authentication, \
			gStatistics.mac.mgt_deauthentication, \
			gStatistics.mac.ctrl_ps_poll, \
			gStatistics.mac.ctrl_rts, \
			gStatistics.mac.ctrl_cts, \
			gStatistics.mac.ctrl_acknowledgement,\
			gStatistics.mac.ctrl_cfp_end, \
			gStatistics.mac.ctrl_cfp_endack, \
			gStatistics.mac.data,\
			gStatistics.mac.data_cf_ack,\
			gStatistics.mac.data_cf_poll,\
			gStatistics.mac.data_cf_ack_poll,\
			gStatistics.mac.data_null_function,\
			gStatistics.mac.data_cf_ack_nod, \
			gStatistics.mac.data_cf_poll_nod, \
			gStatistics.mac.data_cf_ack_poll_nod );

		LogIntoMysql( sqlQuery );
 
		free(sqlQuery);

	}else {
		// file log 
		fclose( gLog.StatisticsFp );
		gLog.StatisticsFp = fopen( gLog.StatisticsLog, "w" );

		fprintf(gLog.StatisticsFp,"mgt_assoc_req %d\n", gStatistics.mac.mgt_assoc_req );
		fprintf(gLog.StatisticsFp,"mgt_assoc_resp %d\n",	gStatistics.mac.mgt_assoc_resp );
		fprintf(gLog.StatisticsFp,"mgt_reassoc_req %d\n", gStatistics.mac.mgt_reassoc_req );
		fprintf(gLog.StatisticsFp,"mgt_reassoc_resp %d\n", gStatistics.mac.mgt_reassoc_resp );
		fprintf(gLog.StatisticsFp,"mgt_probe_req %d\n",	gStatistics.mac.mgt_probe_req );
		fprintf(gLog.StatisticsFp,"mgt_probe_resp %d\n",	gStatistics.mac.mgt_probe_resp );
		fprintf(gLog.StatisticsFp,"mgt_beacon %d\n",	gStatistics.mac.mgt_beacon );
		fprintf(gLog.StatisticsFp,"mgt_atim %d\n", gStatistics.mac.mgt_atim );
		fprintf(gLog.StatisticsFp,"mgt_disass %d\n", gStatistics.mac.mgt_disass );
		fprintf(gLog.StatisticsFp,"mgt_authentication %d\n", gStatistics.mac.mgt_authentication );
		fprintf(gLog.StatisticsFp,"mgt_deauthentication %d\n", gStatistics.mac.mgt_deauthentication );

		fprintf(gLog.StatisticsFp,"ctrl_ps_poll %d\n", gStatistics.mac.ctrl_ps_poll);
		fprintf(gLog.StatisticsFp,"ctrl_rts %d\n", gStatistics.mac.ctrl_rts);
		fprintf(gLog.StatisticsFp,"ctrl_cts %d\n", gStatistics.mac.ctrl_cts);             ;
		fprintf(gLog.StatisticsFp,"ctrl_acknowledgement %d\n", gStatistics.mac.ctrl_acknowledgement ); 
		fprintf(gLog.StatisticsFp,"ctrl_cfp_end %d\n", gStatistics.mac.ctrl_cfp_end ) ;
		fprintf(gLog.StatisticsFp,"ctrl_cfp_endack %d\n", gStatistics.mac.ctrl_cfp_endack );

		fprintf(gLog.StatisticsFp,"data %d\n",	gStatistics.mac.data );
		fprintf(gLog.StatisticsFp,"data_cf_ack %d\n",	gStatistics.mac.data_cf_ack );
		fprintf(gLog.StatisticsFp,"data_cf_poll %d\n",	gStatistics.mac.data_cf_poll );
		fprintf(gLog.StatisticsFp,"data_cf_ack_poll %d\n",	gStatistics.mac.data_cf_ack_poll );
		fprintf(gLog.StatisticsFp,"data_null_function %d\n",	gStatistics.mac.data_null_function );
		fprintf(gLog.StatisticsFp,"data_cf_ack_nod %d\n",	gStatistics.mac.data_cf_ack_nod );
		fprintf(gLog.StatisticsFp,"data_cf_poll_nod %d\n",	gStatistics.mac.data_cf_poll_nod );
		fprintf(gLog.StatisticsFp,"data_cf_ack_poll_nod %d\n",	gStatistics.mac.data_cf_ack_poll_nod );


		fflush( gLog.StatisticsFp );

		//shmdt ( shmaddr );
	}

}
