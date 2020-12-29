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
/* $Id: filter.c,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */

/****************************************************************************
  *
  * filter.c
  *
  * ignore logging current wireless packet by user filter set etc/filter.cfg
  * this module filters packets by types which are loaded at InitFilter() 
  * at etc/filter.cfg
  *
  * last update :
  * 2004/02/22, frog
  *
  ***************************************************************************/

#include "wpacket.h"
#include "filter.h"
#include "cio.h"
#include "config.h"


/*** global variables ***/
extern Config	gConfig ;
Filter filter ;


/*** local variables ***/
static Flist flist[32] = {
	{"MGT_ASSOC_REQ"        ,0x0000}, {"MGT_ASSOC_RESP"       ,0x0010},
	{"MGT_REASSOC_REQ"      ,0x0020}, {"MGT_REASSOC_RESP"     ,0x0030},
	{"MGT_PROBE_REQ"        ,0x0040}, {"MGT_PROBE_RESP"       ,0x0050},
	{"MGT_BEACON"           ,0x0080}, {"MGT_ATIM"             ,0x0090},
	{"MGT_DISASS"           ,0x00A0}, {"MGT_AUTHENTICATION"   ,0x00B0},
	{"MGT_DEAUTHENTICATION" ,0x00C0}, {"CTRL_PS_POLL"         ,0x00a4},
	{"CTRL_RTS"             ,0x00b4}, {"CTRL_CTS"             ,0x00c4},
	{"CTRL_ACKNOWLEDGEMENT" ,0x00d4}, {"CTRL_CFP_END"         ,0x00e4},
	{"CTRL_CFP_ENDACK"      ,0x00f4}, {"DATA"                 ,0x0008},
	{"DATA_CF_ACK"          ,0x0018}, {"DATA_CF_POLL"         ,0x0028},
	{"DATA_CF_ACK_POLL"     ,0x0038}, {"DATA_NULL_FUNCTION"   ,0x0048},
	{"DATA_CF_ACK_NOD"      ,0x0058}, {"DATA_CF_POLL_NOD"     ,0x0068},
	{"DATA_CF_ACK_POLL_NOD" ,0x0078}, {"NONE"                 ,-1}, 
} ;

static Flist f_mark[2] = { {"{", 0 }, {"}", 0 } } ;


/****************************************************************************
  *
  * Function :  InitFilter()
  *
  * Purpose : 
  * read filter.cfg and fill flist[]
  *
  * Arguments : void
  *
  * Returns : 1 == Sucess
  *          -1 == Fail 
  *
  ***************************************************************************/
int 
InitFilter(void) 
{
	FILE *fp ; 
	char buf[256];
	int i=0 , j=0;
	char *ptr ;

	fp = fopen( gConfig.FilterFilename , "r" );
	if ( fp  == NULL ) {
		SysErrorMessage( "InitFilter() : cannot open filter file ");
		return ERROR ;
	}

	memset(buf, '\0', sizeof(buf));
	ptr = fgets(buf, sizeof(buf), fp ) ;
	if ( ptr == NULL ) {
		SysErrorMessage( "InitFilter() : cannot read filter file ");
		return ERROR ;
	}
	if ( strncmp( f_mark[0].field, buf, strlen(f_mark[0].field)) != 0 ) { 
		SysErrorMessage( "InitFilter() : cannot found start mark '{' at line 1 ");
		return ERROR ;
	}
	memset(buf, '\0', sizeof(buf));


	while ( fgets(buf,sizeof(buf),fp) != NULL ) 
	{
		for( i = 0 ; i < 32 ; i++ ) {
			if ( strncmp( flist[i].field, buf, strlen(flist[i].field)) == 0 ) {
				filter.mac_list[j] = flist[i].selnum ;
				j++;
				break;
			}
		}
	}
	
	if ( strncmp( f_mark[1].field, buf, strlen(f_mark[1].field)) == 0 ) { 
			filter.mac_list[j-1] = -1 ;
			filter.mac_list[j] = -1 ;
	}

	fclose(fp);

	/*
	filter.mac_list[0] = MGT_BEACON ;
	filter.mac_list[1] = DATA ;
	filter.mac_list[2] = -1 ;
	*/
	return TRUE;

}




/****************************************************************************
  *
  * Description :
  * it searches the filter[] table and returns "found/not found"
  *
  * Returns : 1 == Found
  *           0 == Not Found
  *
  ***************************************************************************/
int 
MatchFilter( OCTET2 frm_ctrl) 
{
	int i ; int f ;

	f = frm_ctrl & FC_MASK ;

	for ( i = 0 ; i< 32 ;i++ ) {
		if ( filter.mac_list[i] == (unsigned short )-1 )
			return FALSE ;

		else if( f == filter.mac_list[i] )  
			return TRUE;

		else
			continue ;
	}

	SysErrorMessage("filter error occured");
	return FALSE;
}
