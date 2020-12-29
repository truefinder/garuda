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
/* $Id: member.h,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */
/* member.h */

#ifndef	_MEMBER_H
#define _MEMBER_H

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>


#define MAX_OBJECT		2048
#define MAX_TEXTSSID	32
#define	MEMBERTYPE_AP	1
#define MEMBERTYPE_STATION	2

typedef struct _Member {
	int id ;
	int type ;
	time_t first_seen ;
	unsigned char mac[6] __attribute__ ((packed));
	unsigned char bssid[6] __attribute__ ((packed));
	/* case of station */
	struct in_addr ip;
	unsigned char wepflg ;

	/* case of ap */
	unsigned char textssid[MAX_TEXTSSID];
	unsigned char channel ;

	struct _Member *next ;
} Member  ;

typedef struct _MemberHead {
	int total ;
	Member *next ;
} MemberHead ;


int InitMember( void ) ;
void LogMember(void);
void do_member ( MacHdr *ptr , int len );
void LogTrial(MacHdr *ptr, int len );

#endif
