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
/* $Id: chkfrm.c,v 1.3 2004/06/25 08:40:22 seunghyun Exp $ */

/****************************************************************************
  *
  * chkfrm.c 
  *
  * These chk_* functions are the handlers which checks wireless packet fields 
  * between rule field. if both field matches, chk_* function will return unique 
  * number CHK_PKT_* ( it defined at include/wpacket.h ) else it returns 0 
  * every chk_* functions could be called by chk_frm[] function pointer table
  *
  *
  ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"
#include "wpacket.h"
#include "wpktapi.h"



/****************************************************************************
  *
  * Function :
  	chk_type              
	chk_todsflg           
	chk_fromdsflg         
	chk_morefragflg       
	chk_retryflg          
	chk_pwrmgtflg         
	chk_moredatflg        
	chk_wepflg            
	chk_orderflg          
	chk_duration          
	chk_addr1             
	chk_addr2             
	chk_addr3             
	chk_seq               
	chk_addr4             
	chk_mgt_authnum       
	chk_mgt_authseq       
	chk_mgt_beaconinterval
	chk_mgt_capability    
	chk_mgt_currentap     
	chk_mgt_listeninterval
	chk_mgt_reasoncode    
	chk_mgt_associd       
	chk_mgt_statuscode    
	chk_mgt_timestamp     
	chk_mgt_ssid          
	chk_mgt_supportedrates
	chk_mgt_fhparam       
	chk_mgt_dsparam       
	chk_mgt_cfparam       
	chk_mgt_ibssparam     
	chk_mgt_tim           
	chk_mgt_challenge     
	chk_dat_dsap          
	chk_dat_ssap          
	chk_dat_ctrl          
	chk_dat_orgcode       
	chk_dat_proto         
	chk_dat_ip_proto      
	chk_dat_ip_srcip      
	chk_dat_ip_dstip      
	chk_dat_ip_tcp_srcport
	chk_dat_ip_tcp_dstport
	chk_dat_ip_udp_srcport
	chk_dat_ip_udp_dstport
	chk_mgtfprint         
	chk_datfprint         
	chk_ctrlfprint        
	chk_ipfprint          
	chk_tcpfprint         
	chk_udpfprint         
  *
  * Purpose :  these are used for checking current wireless packet field between 
  * rule entry field 
  *
  * Arguments : mp ==> packet pointer
  *             rp ==> rule entry pointer
  *
  * Returns :  CHK_PKT_XXXXXX == if matches, it returns unique number CHK_PKT_*
  *            FALSE == else returns 0
  *
  ***************************************************************************/

//mac header control type
int chk_type(MacHdr *mp, Rule_Entry *rp, int len) 
{
	if (  (mp->frm_ctrl & 0x00ff ) == (rp->rpkt.machdr.frm_ctrl & 0x00ff) ) {
		return CHK_PKT_TYPE ;
	}

	return FALSE ;
}

//mac header to ds flag 
int chk_todsflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ // TODS 
	if ( (mp->frm_ctrl & FCFLG_TODS ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_TODS) )
		return CHK_PKT_TODSFLG ;

	return FALSE; 
}

//mac header from ds flag
int chk_fromdsflg(MacHdr *mp, Rule_Entry *rp, int len) { 
	if ( (mp->frm_ctrl & FCFLG_FROMDS ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_FROMDS) )
		return CHK_PKT_FROMDSFLG ;

	return FALSE; 
}

// mac header more flag
int chk_morefragflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_MOREFRAG ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_MOREFRAG) )
		return CHK_PKT_MOREFRAGFLG ;
	
	return FALSE; 

}

// mac header retry flag
int chk_retryflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_RETRY ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_RETRY) )
		return CHK_PKT_RETRYFLG ;

	return FALSE; 
}

// mac header power management flag
int chk_pwrmgtflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_PWRMGT ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_PWRMGT ) )
		return CHK_PKT_PWRMGTFLG ;

	return FALSE; 
}

// mac header moredata flag
int chk_moredatflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_MOREDATA ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_MOREDATA) )
		return CHK_PKT_MOREDATFLG ;

	return FALSE; 
}

// mac header wep flag
int chk_wepflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_WEP ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_WEP) )
		return CHK_PKT_WEPFLG ;

	return FALSE; 
}

// mac header order flag
int chk_orderflg(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( (mp->frm_ctrl & FCFLG_ORDER ) && (rp->rpkt.machdr.frm_ctrl & FCFLG_ORDER) )
		return CHK_PKT_ORDERFLG ;

	return FALSE; 
}


//dummy reserved 
int chk_dummy_has_not_to_use(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }


//mac header duration
int chk_duration(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( mp->duration == rp->rpkt.machdr.duration )
		return CHK_PKT_DURATION ;

	return FALSE; 
}

//mac header addr1
int chk_addr1(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( ! bcmp( mp->addr1 , rp->rpkt.machdr.addr1 , 6 ) )
		return CHK_PKT_ADDR1 ;

	return FALSE; 
}

//mac header addr2
int chk_addr2(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( ! bcmp( mp->addr2 , rp->rpkt.machdr.addr2 , 6 ) )
		return CHK_PKT_ADDR2 ;


	return FALSE; 
}

//mac header addr3
int chk_addr3(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	if ( ! bcmp( mp->addr3 , rp->rpkt.machdr.addr3 , 6 ) )
		return CHK_PKT_ADDR3 ;


	return FALSE; 
}

//mac header sequence
int chk_seq(MacHdr *mp, Rule_Entry *rp, int len) 
{
	if ( mp->sequence == rp->rpkt.machdr.sequence ) 
		return CHK_PKT_SEQ ;
		
	return FALSE; 
}

//mac header addr4
int chk_addr4(MacHdr *mp, Rule_Entry *rp, int len) 
{
	// check addr4 exist !
	if ( (mp->frm_ctrl & FCFLG_TODS) && (mp->frm_ctrl & FCFLG_FROMDS) ) {

		if ( ! bcmp( mp->addr4 , rp->rpkt.machdr.addr4 , 6 ) )
			return CHK_PKT_ADDR4 ;
	}
	return FALSE; 
}


// mgt section
/*
#define MGTFL_MAX   12

Mlist MgtField_list[12] = {
        {"MGT_ASSOC_REQ",   0x00, FIX_CAPABILITY| FIX_LISTENINTERVAL| VAR_SSID| VAR_SUPPORTEDRATES },
        {"MGT_ASSOC_RESP",  0x10, FIX_CAPABILITY| FIX_STATUS| FIX_AID| VAR_SUPPORTEDRATES },
        {"MGT_REASSOC_REQ", 0x20, FIX_CAPABILITY| FIX_LISTENINTERVAL| FIX_CURRENTAP| VAR_SSID| \
                                    VAR_SUPPORTEDRATES },
        {"MGT_REASSOC_RESP",0x30, FIX_CAPABILITY| FIX_STATUS| FIX_AID| VAR_SUPPORTEDRATES },
        {"MGT_PROBE_REQ",   0x40, VAR_SSID| VAR_SUPPORTEDRATES } ,
        {"MGT_PROBE_RESP",  0x50, FIX_TIMESTAMP| FIX_BEACONINTERVAL| FIX_CAPABILITY| VAR_SSID| \
                                    VAR_SUPPORTEDRATES| VAR_FHPARAM | VAR_DSPARAM | VAR_CFPARAM| VAR_IBSS },
        {"MGT_BEACON",      0x80, FIX_TIMESTAMP| FIX_BEACONINTERVAL| FIX_CAPABILITY| VAR_SSID| \
                                    VAR_SUPPORTEDRATES| VAR_FHPARAM| VAR_DSPARAM| VAR_CFPARAM| \
                                    VAR_IBSS | VAR_TIM },
        {"MGT_ATIM",        0x90, 0 },
        {"MGT_DISASS",      0xa0, FIX_REASON },
        {"MGT_AUTHENTICATION", 0xb0, FIX_AUTHNUM| FIX_AUTHSEQ| FIX_STATUS| VAR_CHALLENGE },
        {"MGT_DEAUTHENTICATION", 0xc0, FIX_REASON },
        {"", -1 , 0 },
} ;
*/

//mgt fixed authnum 2 byte
int chk_mgt_authnum(MacHdr *mp, Rule_Entry *rp, int len) 
{
	unsigned short int *authnum ;

	authnum = (unsigned short int *)get_mgt_fvalue( mp, len, AUTHNUM ) ;
	if ( authnum == NULL)
		return FALSE;

	if ( *authnum == rp->rpkt.mgtbody.f_authnum )
		return CHK_PKT_MGT_AUTHNUM ;


	
	return FALSE; 
}

//mgt fixed authseq 2 byte
int chk_mgt_authseq(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	unsigned short int *authseq ;

	authseq = (unsigned short int *)get_mgt_fvalue( mp, len, AUTHSEQ ) ;
	if ( authseq == NULL)
		return FALSE;

	if ( *authseq == rp->rpkt.mgtbody.f_authseq )
		return CHK_PKT_MGT_AUTHSEQ ;


	return FALSE; 
}

//mgt fixed beacon interval 2 byte 
int chk_mgt_beaconinterval(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	unsigned short int *beacon_interval ;

	beacon_interval = (unsigned short int *)get_mgt_fvalue( mp, len, BEACONINTERVAL );
	if ( beacon_interval == NULL )
		return FALSE;

	if ( *beacon_interval == rp->rpkt.mgtbody.f_binterval ) 
		return CHK_PKT_MGT_BEACONINTERVAL ;


	
	
	return FALSE; 
}

//mgt fixed capability 2 byte
int chk_mgt_capability(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	unsigned short int *capability ;

	capability = (unsigned short int *)get_mgt_fvalue( mp, len, CAPABILITY );
	if ( capability == NULL )
		return FALSE;

	if ( *capability == rp->rpkt.mgtbody.f_capability ) 
		return CHK_PKT_MGT_CAPABILITY ;

	return FALSE; 
}

//mgt fixed currentap  6bytes
int chk_mgt_currentap(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	char * var ;
	var = ( char*) get_mgt_fvalue( mp, len, CURRENTAP ) ;
	if ( var == NULL) 
		return FALSE ;

	if ( ! bcmp ( var , rp->rpkt.mgtbody.f_timestamp, 6 ) ) 
		return CHK_PKT_MGT_CURRENTAP ;

	return FALSE; 
}

//mgt fixed listen interval 2bytes
int chk_mgt_listeninterval(MacHdr *mp, Rule_Entry *rp, int len) 
{
	unsigned short int *var ;

	var = (unsigned short int *)get_mgt_fvalue( mp, len, LISTENINTERVAL );
	if ( var == NULL )
		return FALSE;

	if ( *var == rp->rpkt.mgtbody.f_linterval ) 
		return CHK_PKT_MGT_LISTENINTERVAL ;


	return FALSE; 
}

//mgt fixed reason code 2bytes
int chk_mgt_reasoncode(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	unsigned short int *var ;

	var = (unsigned short int *)get_mgt_fvalue( mp, len, REASONCODE );
	if ( var == NULL )
		return FALSE;

	if ( *var == rp->rpkt.mgtbody.f_reason ) 
		return CHK_PKT_MGT_REASONCODE ;


	return FALSE; 
}

//mgt fixed Assoc id 2bytes
int chk_mgt_associd(MacHdr *mp, Rule_Entry *rp, int len) 
{
	unsigned short int *var ;

	var = (unsigned short int *)get_mgt_fvalue( mp, len, ASSOCID );
	if ( var == NULL )
		return FALSE;

	if ( *var == rp->rpkt.mgtbody.f_aid ) 
		return CHK_PKT_MGT_ASSOCID ;


	return FALSE; 
}

//mgt fixed status code 2bytes
int chk_mgt_statuscode(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	unsigned short int *var ;

	var = (unsigned short int *)get_mgt_fvalue( mp, len, STATUSCODE );
	if ( var == NULL )
		return FALSE;

	if ( *var == rp->rpkt.mgtbody.f_status ) 
		return CHK_PKT_MGT_STATUSCODE ;


	return FALSE; 
}

//mgt fixed timestamp 8bytes
int chk_mgt_timestamp(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	char * var ;
	var = ( char*) get_mgt_fvalue( mp, len, TIMESTAMP ) ;
	if ( var == NULL) 
		return FALSE ;

	if ( ! bcmp ( var , rp->rpkt.mgtbody.f_timestamp, 8 ) ) 
		return CHK_PKT_MGT_TIMESTAMP ;

	return FALSE; 
}



//mgt variable ssid
int chk_mgt_ssid(MacHdr *mp, Rule_Entry *rp, int len) 
{
	/*
	char *tagsp ;
	char ssidtemp[64];
	int lastlen ;
	
	memset( ssidtemp, '\0', sizeof(ssidtemp) );

	tagsp = get_mgt_vstart( mp, len, &lastlen);
	if ( tagsp == NULL ) 
		return FALSE;

	if ( tagsp[0] == 0 && tagsp[1] < 32 )  {
		// ssid element is 0 
		memcpy( ssidtemp, &tagsp[2], tagsp[1] ) ;
		if ( ! strncmp( rp->rpkt.mgtbody.v_ssid, ssidtemp, tagsp[1] ) ) {
			return CHK_PKT_MGT_SSID;
		}

	} else 
		return FALSE; 

	return FALSE ;
	*/

	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_SSID, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_ssid, e.ptr, strlen(rp->rpkt.mgtbody.v_ssid) ) ) {
		return CHK_PKT_MGT_SSID;
	}

	return FALSE ;
	
	
}

//mgt variable supported rates
int chk_mgt_supportedrates(MacHdr *mp, Rule_Entry *rp, int len) 
{
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_SUPPORTEDRATES, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_support, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_SUPPORTEDRATES;
	}
	
	return FALSE; 

}

//mgt variable FH param
int chk_mgt_fhparam(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_FHPARAM, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_fh, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_FHPARAM;
	}
	
	return FALSE; 
}

//mgt variable DS param
int chk_mgt_dsparam(MacHdr *mp, Rule_Entry *rp, int len) 
{
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_DSPARAM, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_ds, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_DSPARAM;
	}
	
	return FALSE; 
}
//mgt variable CF param
int chk_mgt_cfparam(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_CFPARAM, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_cf, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_CFPARAM;
	}
	
	return FALSE; 
}

//mgt variable IBSS param
int chk_mgt_ibssparam(MacHdr *mp, Rule_Entry *rp, int len) 
{
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_IBSSPARAM, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_ibss, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_IBSSPARAM;
	}
	
	return FALSE; 
}
//mgt variable TIM param
int chk_mgt_tim(MacHdr *mp, Rule_Entry *rp, int len) 
{ 	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_TIM, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_tim, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_TIM;
	}
	
	return FALSE; 
}



//mgt variable challenge text
int chk_mgt_challenge(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	int res ;
	Mgt_Element e ;

	res  = get_mgt_vvalue( mp, len, EID_CHALLENGETXT, &e );
	if ( res == FALSE ) 
		return FALSE ;

	if ( ! bcmp( rp->rpkt.mgtbody.v_challenge, e.ptr, e.len ) ) {
		return CHK_PKT_MGT_CHALLENGE;
	}
	
	return FALSE; 
}
               


//data dsap
int 
chk_dat_dsap(MacHdr *mp, Rule_Entry *rp, int len) 
{
	DataHdr *dhp ;

	if ( is_unofficial_datfrm(mp) )
		dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
	else {
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS )
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
		else
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) - 6 );
	}

	if ( dhp->dsap == rp->rpkt.databody.dsap ) {
		/* printf("dsap matched\n"); fflush(stdout); */
		return CHK_PKT_DAT_DSAP ;
	}
	return FALSE; 
}

//data ssap
int 
chk_dat_ssap(MacHdr *mp, Rule_Entry *rp, int len) 
{
	DataHdr *dhp ;

	if ( is_unofficial_datfrm(mp) )
		dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
	else {
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS )
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
		else
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) - 6 );
	}
	
	if ( dhp->dsap == rp->rpkt.databody.ssap ) {
		/* printf("ssap matched\n"); fflush(stdout); */
		return CHK_PKT_DAT_SSAP ;
	}
	return FALSE; 
}

//data control
int 
chk_dat_ctrl(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	DataHdr *dhp ;

	if ( is_unofficial_datfrm(mp) )
		dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
	else {
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS )
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
		else
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) - 6 ); 
	}
	
	if ( dhp->ctrl == rp->rpkt.databody.ctrl ) {
		/* printf("ctrl matched\n"); fflush(stdout); */
		return CHK_PKT_DAT_CTRL ;
	}
	return FALSE; 
}

//data org code
int 
chk_dat_orgcode(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	DataHdr *dhp ;

	if ( is_unofficial_datfrm(mp) )
		dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
	else {
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS )
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
		else
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) - 6 );
	}
	
	if ( ! memcmp( dhp->org_code, rp->rpkt.databody.org_code, 3)  ) {
		/* printf("org code matched\n"); fflush(stdout); */
		return CHK_PKT_DAT_ORGCODE ;
	}
	return FALSE;
}

//data protocol id
int chk_dat_proto(MacHdr *mp, Rule_Entry *rp, int len) 
{ 
	DataHdr *dhp ;


	if ( is_unofficial_datfrm(mp) )
		dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
	else {
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS )
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) ) ;
		else
			dhp = (DataHdr *) ( (char*)mp + sizeof(MacHdr) - 6 );
	}

	if ( dhp->proto_id == rp->rpkt.databody.proto_id ) {
		/* printf("dsap matched\n"); fflush(stdout); */
		return CHK_PKT_DAT_PROTO ;
	}

	return FALSE;
}


//ip protocol
int chk_dat_ip_proto(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }
//ip source ip
int chk_dat_ip_srcip(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }
//ip destination ip
int chk_dat_ip_dstip(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }


//tcp source port
int chk_dat_ip_tcp_srcport(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }
//tcp dest port
int chk_dat_ip_tcp_dstport(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }


//udp source port
int chk_dat_ip_udp_srcport(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }
//udp dest port
int chk_dat_ip_udp_dstport(MacHdr *mp, Rule_Entry *rp, int len) { return FALSE; }



/* Fingerprint partition */
int find_hexes( char *data, char *hexes, int data_len, int hexes_len )
{
	int i =0;

	for( i=0 ; i< data_len ; i++ ) 
	{
		if ( data[i] == hexes[0] ) {
			if ( (i + hexes_len) > data_len )
					return FALSE;

			if (  ! memcmp(&data[i], hexes, hexes_len )  )  {
				return TRUE;
			} 
		}
	}
	return FALSE ;
}


//mgt fingerprint
int chk_mgtfprint(MacHdr *mp, Rule_Entry *rp, int len)   { return FALSE; }

//data fingerprint
int chk_datfprint(MacHdr *mp, Rule_Entry *rp, int len)   
{ 
	char *data_ptr ; 
	int data_len ;
	int hexes_len ;

	if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ){
		data_ptr = ( (char*)mp + sizeof(MacHdr) ) ;
		data_len = len - sizeof(MacHdr) ;
	} else {
		data_ptr = ( (char*)mp + sizeof(MacHdr) - 6 );
		data_len = len - sizeof(MacHdr) -6 ;
	}
	hexes_len = strlen( rp->rpkt.databody.fprint ) ;

	// find hexcodes !!! 
	if ( find_hexes( data_ptr, rp->rpkt.databody.fprint, data_len, hexes_len ) )
		return CHK_PKT_DATFPRINT ;

	return FALSE; 
}

//ctrl fingerprint
int chk_ctrlfprint(MacHdr *mp, Rule_Entry *rp, int len)   { return FALSE; }


//ip fingerprint
int chk_ipfprint(MacHdr *mp, Rule_Entry *rp, int len)   { return FALSE; }
//tcp fingerprint
int chk_tcpfprint(MacHdr *mp, Rule_Entry *rp, int len)   { return FALSE; }
//udp fingerprint
int chk_udpfprint(MacHdr *mp, Rule_Entry *rp, int len)   { return FALSE; }


