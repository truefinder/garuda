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
/* $Id: init.c,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */
/****************************************************************************
 *
 * init.c 
 *
 * initialization of log directory, system message, signal handler, 
 * event handler(checker), device, pattern rule ... etc
 * 
 *
 *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "garuda.h"
#include "rule.h"
#include "wpacket.h"
#include "cio.h"
#include "fetch.h"
#include "mesg.h"
#include "init.h"
#include "chkfrm.h"
#include "session.h"
#include "config.h"
#include "log.h"
#include "detect.h"

/*** Global variables ***/
extern Config	gConfig ;
extern Log	gLog ;
extern Rule_Entry rule[MAX_RULE] ;
extern Rule_Entry rule_internal[MAX_RULE_INTERNAL];
extern int (* check_frm[MAX_CHECKER])(MacHdr *mp, Rule_Entry *rp, int n ) ;

/*** global function ***/
extern int LoadRule(void); // from rule.y
extern void Clear(int); // from init.h


/*** Internal fuctions ***/
void DefaultChecker(MacHdr *mp, Rule_Entry *rp, int n);
void SetRealChecker( void )  ;



/****************************************************************************
  *
  * Function : InitLogdir()
  *
  * Purpose : 
  * check if log directory exist and is writable 
  *
  * Arguments : none
  *
  * Returns : 1 == Sucess
  *           -1 == Error
  *
  ***************************************************************************/
int InitLogdir ( void ) 
{
	struct stat buf;
	int res ;
	char testpath[256];

	snprintf( testpath, sizeof(testpath), "%s/%s", gConfig.LogDirectory, "test");

	if ( stat( gConfig.LogDirectory, &buf ) < 0  ) 
		return ERROR;

	if ( (res = creat( testpath, S_IWUSR|S_IRUSR|S_IWOTH)) < 0 ) 
			return ERROR ;

	unlink( testpath );

	return TRUE ;
}


/****************************************************************************
  *
  * Function : InitSysmsg()
  *
  * Purpose : 
  * init system.log
  *
  * Arguments : none
  *
  * Returns : 1 == Sucess
  *           -1 == Error
  *
  ***************************************************************************/
int
InitSysmsg( void )
{

	gLog.SystemFp = fopen( gLog.SystemLog , "a" ) ;
	if ( gLog.SystemFp == NULL )  {
		return ERROR;
	}

	return TRUE ;
}



/****************************************************************************
  *
  * Function : InitSignal()
  *
  * Purpose :  
  * init die signal 
  * set timer to refresh statistics and session info
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/
void
InitSignal(void)
{
	struct itimerval value, ovalue ;

	// timer setting
	// do_period() will call do_statistics() and do_session() periodically
	// these will refresh session info and statistics info
	value.it_value.tv_sec = value.it_interval.tv_sec = PERIOD_TIME ;
	value.it_value.tv_usec = value.it_interval.tv_usec = 0 ;
	
	signal( SIGALRM, do_period );
	setitimer( ITIMER_REAL, &value, &ovalue );


	// Clear() if signal reached.
	signal( SIGQUIT, Clear);
	signal( SIGINT, Clear );
	signal( SIGKILL, Clear);
	signal( SIGSTOP, Clear );

	return ;

}

/****************************************************************************
  *
  * Function : InitChecker()
  *
  * Purpose : set "packet field checker" into check_frm[]
  *
  * Arguments : void
  *
  * Returns : void
  *
  ***************************************************************************/

void 
DefaultChecker(MacHdr *mp, Rule_Entry *rp, int n)
{
	return ;
}

void
InitChecker(void)
{
	int i;
	for ( i=0 ; i< 60000 ; i++ ) {
		check_frm[i] = (void*)DefaultChecker ;
	}

	SetRealChecker();

	return ;
}

void 
SetRealChecker( void ) 
{
	/* initializing cheker */

	check_frm[ CHK_PKT_TYPE               ] = (void*) chk_type                 ;
	check_frm[ CHK_PKT_TODSFLG            ] = (void*) chk_todsflg              ;
	check_frm[ CHK_PKT_FROMDSFLG          ] = (void*) chk_fromdsflg            ;
	check_frm[ CHK_PKT_MOREFRAGFLG        ] = (void*) chk_morefragflg          ;
	check_frm[ CHK_PKT_RETRYFLG           ] = (void*) chk_retryflg             ;
	check_frm[ CHK_PKT_PWRMGTFLG          ] = (void*) chk_pwrmgtflg            ;
	check_frm[ CHK_PKT_MOREDATFLG         ] = (void*) chk_moredatflg           ;
	check_frm[ CHK_PKT_WEPFLG             ] = (void*) chk_wepflg               ;
	check_frm[ CHK_PKT_ORDERFLG           ] = (void*) chk_orderflg             ;
	check_frm[ CHK_PKT_DURATION           ] = (void*) chk_duration             ;
	check_frm[ CHK_PKT_ADDR1              ] = (void*) chk_addr1                ;
	check_frm[ CHK_PKT_ADDR2              ] = (void*) chk_addr2                ;
	check_frm[ CHK_PKT_ADDR3              ] = (void*) chk_addr3                ;
	check_frm[ CHK_PKT_SEQ                ] = (void*) chk_seq                  ;
	check_frm[ CHK_PKT_ADDR4              ] = (void*) chk_addr4                ;
	check_frm[ CHK_PKT_MGT_AUTHNUM        ] = (void*) chk_mgt_authnum          ;
	check_frm[ CHK_PKT_MGT_AUTHSEQ        ] = (void*) chk_mgt_authseq          ;
	check_frm[ CHK_PKT_MGT_BEACONINTERVAL ] = (void*) chk_mgt_beaconinterval   ;
	check_frm[ CHK_PKT_MGT_CAPABILITY     ] = (void*) chk_mgt_capability       ;
	check_frm[ CHK_PKT_MGT_CURRENTAP      ] = (void*) chk_mgt_currentap        ;
	check_frm[ CHK_PKT_MGT_LISTENINTERVAL ] = (void*) chk_mgt_listeninterval   ;
	check_frm[ CHK_PKT_MGT_REASONCODE     ] = (void*) chk_mgt_reasoncode       ;
	check_frm[ CHK_PKT_MGT_ASSOCID        ] = (void*) chk_mgt_associd          ;
	check_frm[ CHK_PKT_MGT_STATUSCODE     ] = (void*) chk_mgt_statuscode       ;
	check_frm[ CHK_PKT_MGT_TIMESTAMP      ] = (void*) chk_mgt_timestamp        ;
	check_frm[ CHK_PKT_MGT_SSID           ] = (void*) chk_mgt_ssid             ;
	check_frm[ CHK_PKT_MGT_SUPPORTEDRATES ] = (void*) chk_mgt_supportedrates   ;
	check_frm[ CHK_PKT_MGT_FHPARAM        ] = (void*) chk_mgt_fhparam          ;
	check_frm[ CHK_PKT_MGT_DSPARAM        ] = (void*) chk_mgt_dsparam          ;
	check_frm[ CHK_PKT_MGT_CFPARAM        ] = (void*) chk_mgt_cfparam          ;
	check_frm[ CHK_PKT_MGT_IBSSPARAM      ] = (void*) chk_mgt_ibssparam        ;
	check_frm[ CHK_PKT_MGT_TIM            ] = (void*) chk_mgt_tim              ;
	check_frm[ CHK_PKT_MGT_CHALLENGE      ] = (void*) chk_mgt_challenge        ;
	check_frm[ CHK_PKT_DAT_DSAP           ] = (void*) chk_dat_dsap             ;
	check_frm[ CHK_PKT_DAT_SSAP           ] = (void*) chk_dat_ssap             ;
	check_frm[ CHK_PKT_DAT_CTRL           ] = (void*) chk_dat_ctrl             ;
	check_frm[ CHK_PKT_DAT_ORGCODE        ] = (void*) chk_dat_orgcode          ;
	check_frm[ CHK_PKT_DAT_PROTO          ] = (void*) chk_dat_proto            ;
	check_frm[ CHK_PKT_DAT_IP_PROTO       ] = (void*) chk_dat_ip_proto         ;
	check_frm[ CHK_PKT_DAT_IP_SRCIP       ] = (void*) chk_dat_ip_srcip         ;
	check_frm[ CHK_PKT_DAT_IP_DSTIP       ] = (void*) chk_dat_ip_dstip         ;
	check_frm[ CHK_PKT_DAT_IP_TCP_SRCPORT ] = (void*) chk_dat_ip_tcp_srcport   ;
	check_frm[ CHK_PKT_DAT_IP_TCP_DSTPORT ] = (void*) chk_dat_ip_tcp_dstport   ;
	check_frm[ CHK_PKT_DAT_IP_UDP_SRCPORT ] = (void*) chk_dat_ip_udp_srcport   ;
	check_frm[ CHK_PKT_DAT_IP_UDP_DSTPORT ] = (void*) chk_dat_ip_udp_dstport   ;
	check_frm[ CHK_PKT_MGTFPRINT          ] = (void*) chk_mgtfprint            ;
	check_frm[ CHK_PKT_DATFPRINT          ] = (void*) chk_datfprint            ;
	check_frm[ CHK_PKT_CTRLFPRINT         ] = (void*) chk_ctrlfprint           ;
	check_frm[ CHK_PKT_IPFPRINT           ] = (void*) chk_ipfprint             ;
	check_frm[ CHK_PKT_TCPFPRINT          ] = (void*) chk_tcpfprint            ;
	check_frm[ CHK_PKT_UDPFPRINT          ] = (void*) chk_udpfprint            ;


	return ;
}


/****************************************************************************
  *
  * Function : InitDevice( char *)
  *
  * Purpose : init sniffing device
  *
  * Arguments : device ==> case of offline : filename, 
  *                        case of live : device name
  *
  * Returns : pcap_t * == pcap handle pointer
  *           NULL     == NULL pointer
  *
  ***************************************************************************/
pcap_t * 
InitDevice( char *device ) 
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *tmp_handle ;

	if ( gConfig.off ) {
		if (  (tmp_handle = pcap_open_offline( device, errbuf )) == NULL ) {
			SysErrorMessage("InitDevice() : sample file cannot be opened ");
			return NULL;
		}
	}else{
		if (  (tmp_handle = pcap_open_live( device, 65536, 1, 1000, errbuf )) == NULL ) {
			SysErrorMessage("InitDevice() : device cannot be opened ");
			return NULL;
		}

	}

	return  tmp_handle;
}


/****************************************************************************
  *
  * Description :
  * init rule set by calling LoadRule()
  *
  * Returns : 1 == Success
  *          -1 == Fail 
  ***************************************************************************/
int
InitRule( void ) 
{
	int i ;

	memset ( rule, '\0', sizeof(rule) );

	// LoadRule() in rule.y 
	if ( LoadRule () <  0 ) {
		SysErrorMessage("LoadRule() : cannot load rules successfuly ");
		return ERROR ;
	}


	/* start of internal rule setting */
	for ( i = 0 ; i < MAX_RULE_INTERNAL ; i++ ) 
	{
		rule_internal[i].id = i ;
		rule_internal[i].d_type = 0 ;
		rule_internal[i].count = 0 ;
		rule_internal[i].timer = 0 ;
		rule_internal[i].risk = 0 ;
	}

	rule_internal[IRN_NULLPROBE].risk =3 ; // warn 
	rule_internal[IRN_NULLASSOC].risk = 3; // warn
	rule_internal[IRN_MACSPOOF].risk = 5 ; // critical
	rule_internal[IRN_ROGUEAP].risk = 4 ; // high


	return TRUE;
}



/****************************************************************************
  *
  * Description : 
  * InitDatastruct() init "status" related data structure
  * 
  *
  ***************************************************************************/

int SetSystemStack(void) {
	return TRUE;
}

int SetSystemPool(void) {
	return TRUE;
}

void 
InitDatastruct(void)
{
	SetSystemStack();
	SetSystemPool();

	return ;
}




