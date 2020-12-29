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
/* $Id: config.h,v 1.2 2004/06/23 09:14:18 seunghyun Exp $ */
/* config.h */

#ifndef _CONFIG_H
#define _CONFIG_H


#define SHMKEY_STATISTICS	0x1000
#define SHMKEY_SESSION		0x2000

#define LOG_DETECT		"detect.log"
#define LOG_SYSTEM		"system.log"
#define LOG_STATISTICS		"statistics.log"
#define LOG_SESSION		"session.log"
#define LOG_MEMBER		"member.log"
#define LOG_TRIAL		"trial.log"

#define PERIOD_TIME	3
#define OFFLINE_NANOSLEEP	120000000

#define MAX_OPTSTR	128
#define MAX_PATH	256
#define MAX_TRUSTAP	16

/* config symbol definition */
#define CNF_SERVERNAME    	1
#define CNF_GARUDAROOT    	2
#define CNF_DEVICENAME    	3
#define CNF_DEAMONMODE    	4
#define CNF_SIMULATIONMODE	5
#define CNF_LOGDIRECTORY  	6
#define CNF_FILTERFILE    	7
#define CNF_RULEFILE      	8
#define CNF_SAMPLEFILE    	9
#define CNF_TRUSTAPLIST   	10
#define CNF_MYSQLUSE		11
#define CNF_MYSQLHOST		12
#define CNF_MYSQLUSER		13
#define CNF_MYSQLPASS		14

typedef struct _APMacList {
	unsigned char mac[MAX_TRUSTAP][6];

} APMacList ;

typedef struct _Config {
	int cfn ; // config filename
	int ffn ; // filter filename
	int rfn ; // rule filename
	int dfn ; // device filename
	int ld ;  // log directory
	int mode_deamon ;
	int sfn ; // sample filename
	int off ;
	int mysql_use ; // for mysql support

	char FilterFilename[MAX_OPTSTR];
	char RuleFilename[MAX_OPTSTR];
	char LogDirectory[MAX_OPTSTR];

	char DeviceName[MAX_OPTSTR];
	char SampleFilename[MAX_OPTSTR];

	char ConfigFilename[MAX_OPTSTR];

	/* read from garuda.conf */
	char ServerName[MAX_OPTSTR];
	char GarudaRoot[MAX_PATH];
	APMacList	TrustAPList ;
	int TrustAPNum ;

	/* config for mysql connection */
	char MysqlHost[MAX_OPTSTR];
	char MysqlUser[MAX_OPTSTR];
	char MysqlPass[MAX_OPTSTR];

} Config ;


typedef struct _Log {
	char SystemLog[MAX_PATH];
	char DetectLog[MAX_PATH];
	char SessionLog[MAX_PATH];
	char StatisticsLog[MAX_PATH];
	char MemberLog[MAX_PATH];
	char TrialLog[MAX_PATH];
	FILE *SystemFp , *StatisticsFp , *SessionFp, *MemberFp, *TrialFp ;
	int DetectFd ;

} Log ;

#define REALPATH(ptr,dir,filename)  do{ \
	ptr = malloc(MAX_PATH ) ; \
	snprintf( ptr , MAX_PATH ,"%s/%s",  dir, filename); \
} while(0) 

#define FREEPATH(ptr) free(ptr) 


int LoadConfig( char *filepath ) ;
int InitConfigInput( char *filepath );




#endif

