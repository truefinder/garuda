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
/* $Id: garuda.c,v 1.3 2004/06/23 09:14:18 seunghyun Exp $ */

/****************************************************************************
 * garuda.c 
 *
 * command line parsing, global variable initialization, 
 * make a device sniffing-mode
 *
 *
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <asm/types.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <mysql/mysql.h>
#include "garuda.h"
#include "cio.h"
#include "decode.h"
#include "init.h"
#include "fetch.h"
#include "wpacket.h"
#include "session.h"
#include "mesg.h"
#include "log.h"
#include "config.h"
#include "member.h"
#include "detect.h"
#include "mysql.h"

#define LOAD_INITFUNC( str1,str2,message) do { \
	SysInitMessage( message ) ; \
	if ( str1 ## str2() < 0 ) { \
		SysFailMessage();  \
		res--;  \
	} else \
		SysOkMessage(); \
} while(0) 


/*** Global variables  ***/
Config		gConfig ;
pcap_t * 	pHandle ; 
Log		gLog ;
MYSQL		mysql ;


Rule_Entry      rule[MAX_RULE] ;  /* Pattern rule */
Rule_Entry	rule_internal[MAX_RULE_INTERNAL];

int (* check_frm[MAX_CHECKER])(MacHdr *mp, Rule_Entry *rp, int n ) ;


/*** Local variables ***/
static char		*current_version = "1.0a" ;


/*** Internal fuctions ***/
void PreSet( void );
int InitGaruda(void);
void ParseCmdline( int argc, char *argv[] ) ;
void StartSniff( pcap_t * pHandle);
void PacketHandler( u_char *param, const struct pcap_pkthdr *header, const u_char * pkt_data ) ;
void SysHang( void );
int Clear(int);
void Help( void );
void Version(void);


/****************************************************************************
  *
  * Function : main( int , char **)
  *
  * Purpose : garuda start point, 
  * parse commands line and launch body
  *
  * Arguments :	argc, argv ==> command-line arguments
  *
  * Returns : 0 == successfuly done
  *          -1 == error
  *
  ***************************************************************************/
int 
main( int argc, char *argv[] ) 
{
#ifdef LOVE_FROG
	time_t ts ;
	char start_mesg[128];
	int pid ;

	ParseCmdline( argc , argv );

	// DEAMON mode 
	if ( gConfig.mode_deamon )  {
		// Error
		if ( (pid = fork() ) < 0 ) {
			SysErrorExit("fork() : cannot create child process");

		// Parent
		} else if ( pid > 0 ) {
			close(0); 
			close(1); 
			//close(2); 
			return 0 ; 

		// Child
		} else {	
			if ( InitGaruda() <0)
				SysErrorExit(" Initialization failed ");

			ts = time(&ts) ;
			sprintf( start_mesg, "%s at %s", SYSM_START, (char*)ctime( &ts) );
			SysMessage(start_mesg);

			// if debug mode had been set, dont' close console in-out
#ifndef	DEBUGZ
			close(0);
			close(1);
			close(2);
#endif
			StartSniff(pHandle);
			SysHang();

			Clear(0);
		}

	// CONSOLE mode
	} else  { 
			if (InitGaruda() < 0)
				SysErrorExit("Initialization failed ");

			ts = time(&ts) ;
			sprintf( start_mesg, "%s at %s", SYSM_START, (char*)ctime( &ts) );
			SysMessage(start_mesg);

			StartSniff(pHandle);

			SysHang();

			Clear(0);
	}

#endif // LOVE_FROG
	return 0;
}


/****************************************************************************
  *
  * Functions : ParseCmdline( int, char ** )
  *
  * Purpose : parse command-line and set gConfig
  *
  * Arguments :	argc, argv ==> command-line arguments
  *
  * Returns : void
  *
  ***************************************************************************/
static char optstr[] = "f:i:L:r:s:c:DShv" ;

void ParseCmdline( int argc, char *argv[] )
{
	extern char *optarg ;
	extern int optind ;
	extern int opterr ;
	int ch ;

	memset( &gConfig, '\0', sizeof(Config) );

	if ( argc < 2 ) {
		Help();
		exit(-1);
	}

	while( (ch=getopt(argc , argv, optstr)) != -1) {
		switch(ch) {
			case 'c' : // config file
				strncpy( gConfig.ConfigFilename, optarg, MAX_OPTSTR );
				gConfig.cfn = 1;
				break;

			case 'f' : // filter filename 
				strncpy( gConfig.FilterFilename, optarg , MAX_OPTSTR );
				gConfig.ffn = 1 ;
				break;

			case 'h': // help 
				Help();
				exit(0);

			case 'i': // device filename
				strncpy( gConfig.DeviceName, optarg , MAX_OPTSTR );
				gConfig.dfn = 1;
				break;
			
			case 'r' : // rule filename
				strncpy( gConfig.RuleFilename, optarg , MAX_OPTSTR );
				gConfig.rfn = 1 ;
				break;

			case 's': // daumped sample 802.11 file name
				strncpy( gConfig.SampleFilename, optarg, MAX_OPTSTR );
				gConfig.sfn = 1 ;
				break;

			case 'S': // simulating mode
				gConfig.off = 1;
				break;

			case 'D': // deamon mode
				gConfig.mode_deamon = 1;
				break;

			case 'L': // log directory
				strncpy( gConfig.LogDirectory, optarg, MAX_OPTSTR );
				gConfig.ld = 1;
				break;

			case 'v': // version information
				Version();
				exit(0);

			default:
				break;
		}
	}

	if ( gConfig.cfn )  {
		LoadConfig(gConfig.ConfigFilename);
		/*** stop for config file debug ***/
		// while(1){ printf("hang\n");sleep(3); }

	} // garuda.conf existed ...
	else {
		///////// check command-line options /////////////
		if ( !(gConfig.ffn && gConfig.rfn && gConfig.ld) ) {
			printf("\n");
			printf(" you need to set option -f <filter filename> \n"
			       "             and option -r <rule filename> \n"
			       "             and option -L <log directory> correctly \n"
			       "\n"
			       " or you need to set option -c <config filename> \n");
			printf("\n\n");
			exit(-1);
		}

		if ( ! gConfig.dfn ) {
		  if ( !(gConfig.off && gConfig.sfn) ) {
			printf("\n");
			printf(" you need to set option -i <device filename> for real-time \n" \
			       "              or option -S -s <sample filename> for simulating dumped packet\n"
			       "\n"
			       " or you need to set option -c <config filename> \n");
			printf("\n\n");
			exit(-1);
		  }

		}
	}

	snprintf( gLog.SystemLog, MAX_PATH, "%s/%s", gConfig.LogDirectory, LOG_SYSTEM );
	snprintf( gLog.StatisticsLog, MAX_PATH,"%s/%s", gConfig.LogDirectory, LOG_STATISTICS );
	snprintf( gLog.DetectLog, MAX_PATH,"%s/%s", gConfig.LogDirectory, LOG_DETECT );
	snprintf( gLog.SessionLog, MAX_PATH,"%s/%s", gConfig.LogDirectory, LOG_SESSION );
	snprintf( gLog.MemberLog, MAX_PATH,"%s/%s", gConfig.LogDirectory, LOG_MEMBER );
	snprintf( gLog.TrialLog, MAX_PATH,"%s/%s", gConfig.LogDirectory, LOG_TRIAL );

	return ;
}


/****************************************************************************
  *
  * Function : PreSet()
  *
  * Purpose : 
  * pre-initialization function
  * set log directory, system console, signal and internal functions
  *
  * Arguments : void
  *
  * Returns : void
  *
 ***************************************************************************/
void
PreSet(void)
{
	if ( InitLogdir() < 0 ) {
		SysErrorMessage("log directory could not be initialized.");
		SysErrorExit("InitLogdir()");
	}

	if ( InitSysmsg() < 0 ) {
		SysErrorMessage("system message could not be initialized.");
		SysErrorExit("InitSysmsg()" );
	}

	if ( InitMysql() < 0 ) { 
		SysErrorMessage("mysql database support could not be initialized.");
		SysErrorExit("InitMysql()" );
	}

	/* initilization  Rule,  */
	if ( InitRule() < 0) {
		SysErrorMessage("rule could not be initialized.");
		SysErrorExit("InitRule()" );
	}

	/*
	if ( InitFilter() < 0) {
		SysErrorMessage("filter could not be initialized. ");
		SysErrorExit("InitFilter()");
	}
	*/


	InitSignal()  ;
	InitChecker();

	/* nothing to init today in InitDatastruct() */
	InitDatastruct();

	return ;
}


/*****************************************************************************
  * 
  * Function : InitGaruda()
  *
  * Purpose : 
  *  Initialize garuda body
  *
  *  init list are below
  *  log directory, system message, signal handler, event handler, 
  *  common data structure, filter ,rule, device, session, statistics, 
  *  member, attack related data structure and log file
  *
  * Arguments : none
  *
  * Returns : 0 == Initialization success
  *          -1 == fail
  *
  ****************************************************************************/
int InitGaruda( void ) 
{
	int res = 0;

	/* PreSet() is the pre-initialization function
	 * log directory, system message file, filter , rule ,
	 * signal handler, event handler and common data structure
	 */
	PreSet();
	SysInitMessage(SYSMI_PRESET); 
	SysOkMessage();

	/* initialization of device */
	if ( gConfig.off ) {
		// OFFLINE mode 
		SysInitMessage(SYSMI_DEVICE);
		if ( (pHandle = InitDevice(gConfig.SampleFilename)) == NULL ) {
			SysFailMessage();	
			res-- ;
		}
		SysOkMessage();
	} else { // REAL-TIME mode 
		SysInitMessage(SYSMI_DEVICE);
		if ( (pHandle = InitDevice(gConfig.DeviceName)) == NULL ) {
			SysFailMessage();
			res-- ;
		}
		SysOkMessage();
	}

	LOAD_INITFUNC( Init, Filter, SYSMI_FILTER );

	LOAD_INITFUNC( Init, Statistics, SYSMI_STATISTICS ) ;
	LOAD_INITFUNC( Init, Session, SYSMI_SESSION ) ;
	LOAD_INITFUNC( Init, Member, SYSMI_MEMBER );
	LOAD_INITFUNC( Init, Detect, SYSMI_DETECT );

	fflush(stdout);

	if ( res < 0 )
		return ERROR ;

	return TRUE;

}


/****************************************************************************
  *
  * Function : Clear( int )
  *
  * Purpose : release all resource to system
  *
  * Arguments : sig ==> dummy value
  *
  * Returns :	0 == success 
  *
  ***************************************************************************/
int
Clear (int sig)
{
	if ( gLog.SystemFp )
		fclose( gLog.SystemFp );
	
	if ( gLog.SessionFp )
		fclose( gLog.SessionFp );

	if ( gLog.StatisticsFp )
		fclose( gLog.StatisticsFp );

	if ( gLog.MemberFp )
		fclose( gLog.MemberFp );

	if ( gLog.DetectFd > 0 )
		close(gLog.DetectFd);

	if ( gConfig.mysql_use ) 
		mysql_close(&mysql ) ;

	SysMessage(SYSM_STOP);
	SysMessage("\n\n");

	sleep(1);

	if ( gConfig.mode_deamon )
		return 0 ;

	exit(0);


}


/****************************************************************************
  *
  * Function : StartSniff( pcap_t *)
  *
  * Purpose : start sniffing by calling pcap_loop()
  *
  * Arguments : pHandle => pcap_open_xxxx handler descriptor
  *
  * Returns : none
  *
  ***************************************************************************/
void 
StartSniff( pcap_t * pHandle)
{
	SysMessage(SYSM_SNIFF); 

	pcap_loop( pHandle, 0, PacketHandler, NULL );

	return ;
}


void 
PacketHandler( u_char *param, const struct pcap_pkthdr *header, \
		const u_char * pkt_data )
{
	FetchWlanPacket( pkt_data, header->len );
#ifdef DEBUGZ
	//show_wlanpkt( pkt_data, header->len ); // from decode.c
#endif

	return ;	
}


void SysHang( void ) 
{
	SysMessage("packet analisys is done,  system is hanging now");
	while(1) {
		sleep(10) ;
	}

	return ;
}


void Help( void )
{
	char *menu = \
		"usage : garuda [-f filename] [-r filename] [-L directory] [-c filename] [-i device | -S -s filename] [-D] [-h|-v] \n\n" \
		"\t -f <filename>  : set filter filename  \n" \
		"\t -r <filename>  : set rule filename    \n" \
		"\t -L <directory> : set log directory    \n"\
		"\t -i <device>    : set device name      \n" \
		"\t -S             : set Simulation mode  \n"\
		"\t -s <filename>  : set sample filename  \n" \
		"\t -D             : set Deamon mode  \n"\
		"\t -c <filename>  : set config filename \n"\
		"\t -h             : this page            \n" \
		"\t -v             : version of garuda    \n" \
		;

	printf("%s , %s\n\n", "garuda", current_version );
	printf("%s\n", menu );

	return;
}

void Version(void)
{
	printf("%s , %s\n\n", "garuda", current_version );
	return;
}
