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
/* $Id: wpktapi.c,v 1.4 2004/06/25 08:40:22 seunghyun Exp $ */
/****************************************************************************
  *
  * wpktapi.c
  *
  * wpktapi is wireless packet api to extract field values from 802.11 
  * wireless packet. you can return value after calling each functions 
  *
  *
  ***************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include "type.h"
#include "wpacket.h"
#include "wpktapi.h"


/****************************************************************************
  *
  * You can get a value you want from wireless packet 
  *
  * MAC header : 
  * 	get_frmtype
  *	get_srcmac, get_dstmac, get_bssidmac
  * 
  * MGT header
  * 	get_mgt_fstart, get_mgt_fvalue 
  *	get_mgt_vstart, get_mgt_vvalue
  *
  * DATA header
  *	get_dat_srcip, get_dat_dstip
  *	get_dat_srcport, get_dat_dstport
  *
  ***************************************************************************/

// to get frame control 
unsigned short int
get_frmtype ( MacHdr *mp ) 
{
	return ( mp->frm_ctrl & FC_MASK) ;
}

void 
wnet_mtos ( char *pdst , const char *psrc )
{
        snprintf( pdst, 32, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", \
                    psrc[0], \
                    psrc[1], \
                    psrc[2], \
                    psrc[3], \
                    psrc[4], \
                    psrc[5] \
                   );
}

void 
wnet_stom( char *pdst, const char *psrc ) 
{
	sscanf( psrc, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", \
			&pdst[0], \
			&pdst[1], \
			&pdst[2], \
			&pdst[3], \
			&pdst[4], \
			&pdst[5] \
			);

}

char* 
get_srcmac( MacHdr *mp )
{
    char *addr_ptr = NULL ; 

    switch ( COOK_FRAME_TYPE(mp->frm_ctrl)) {
	    case MGT_FRAME:
		    addr_ptr = (char *)&mp->addr2 ;
		    break; 

	    case DATA_FRAME:
		    if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			    addr_ptr = ( char*) &mp->addr4 ;
			    break;
		    }
		    if ( mp->frm_ctrl & FCFLG_FROMDS ) { 
			    addr_ptr = (char *)&mp->addr3 ; 
			    break; 
		    }
		    if ( mp->frm_ctrl & FCFLG_TODS ) {
			    addr_ptr = ( char*)&mp->addr2 ;
			    break;
		    }
		    else // case 0 
			    addr_ptr = (char*) &mp->addr2 ; 	
			    break;

	    case CONTROL_FRAME:
			    break; 

	    default: 
			return NULL; 
    }       

    return addr_ptr;
}

char* 
get_dstmac( MacHdr *mp )
{
    char *addr_ptr = NULL ; 

    switch ( COOK_FRAME_TYPE(mp->frm_ctrl)) { 
	    case MGT_FRAME:
		    addr_ptr = (char *)&mp->addr1 ;
		    break; 
	    case DATA_FRAME: 
		    if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			    addr_ptr = ( char*) &mp->addr3 ;
			    break;
		    }
		    if ( mp->frm_ctrl & FCFLG_FROMDS ) { 
			    addr_ptr = (char *)&mp->addr1 ; 
			    break; 
		    }
		    if ( mp->frm_ctrl & FCFLG_TODS ) {
			    addr_ptr = ( char*)&mp->addr3 ;
			    break;
		    }
		    else // case 0
			   addr_ptr = (char*) &mp->addr1 ; 
		    	break;

	    case CONTROL_FRAME:
			break; 

	    default: 
		    return NULL;
    }       
    return addr_ptr;
}

char*
get_bssidmac( MacHdr *mp)
{
    char *addr_ptr = NULL ; 

    switch ( COOK_FRAME_TYPE(mp->frm_ctrl)) {
	case MGT_FRAME:
            addr_ptr = (char *)&mp->addr3 ;
            break; 
               
	case DATA_FRAME:
	    if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
		    // no ssid
		    return NULL;
	    }
            if ( mp->frm_ctrl & FCFLG_FROMDS ) { 
		    addr_ptr = (char *)&mp->addr2 ; 
		    break; 
	    }
	    if ( mp->frm_ctrl & FCFLG_TODS ) {
		    addr_ptr = ( char*)&mp->addr1 ;
		    break;
	    }
	    else // case 0
		   addr_ptr = (char*) &mp->addr3 ;
		    break;

	case CONTROL_FRAME:
		break;

        default: 
	    return NULL;
    }

    return addr_ptr;
}


/****************************************************************************
  *
  * Function : is_unofficial_datfrm()
  *
  * Purpose : check if current wireless data frame packet is an official stuff
  *           based by ISO
  *
  * Arguments : mp ==> current wireless packet pointer
  *
  * Returns : TRUE (1) it's an unofficial data frame
  *           FALSE (0) it's an official one
  *
  ***************************************************************************/
int 
is_unofficial_datfrm( MacHdr *mp ) 
{
	 typedef struct _dummy_datafrm {
		unsigned char dsap ; // (8bits)
		unsigned char ssap ; // (8bits)
	} dummy_datfrm   ;

	 dummy_datfrm *datfrm_ptr ;

	datfrm_ptr = ( dummy_datfrm *) ((char*)mp + sizeof( MacHdr ) ) ;

	// check dsap ,ssap
	// TRUE : it's an unofficial data frame, it didn't omitted address 4
	if ( datfrm_ptr->dsap == 0xaa && datfrm_ptr->ssap == 0xaa ) 
		return TRUE ; 
	else 
		return FALSE ; 
		// it's an official data frame, omits address 4
}


struct in_addr *
get_dat_srcip ( MacHdr *mp )
{
	DataHdr *datahdr ;
	IPHdr *iphdr ;

	if ( COOK_FRAME_TYPE(mp->frm_ctrl) != DATA_FRAME )
		return NULL; 

	if ( is_unofficial_datfrm(mp ) )
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
	else {
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) - 6 )  ;
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
		}
	}

	// is IP protocol ?
	if ( datahdr->proto_id != 0x0008 ) { 
		return NULL ;
	}

	iphdr = (IPHdr*) ( (char*)datahdr + sizeof( DataHdr ) );

	return &iphdr->ip_src;

}

struct in_addr *
get_dat_dstip ( MacHdr *mp )
{
	DataHdr *datahdr ;
	IPHdr *iphdr ;

	if ( COOK_FRAME_TYPE(mp->frm_ctrl)  != DATA_FRAME )
		return NULL; 

	if ( is_unofficial_datfrm(mp ) )
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
	else{
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) - 6 )  ;
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
		}
	}

	if ( datahdr->proto_id != 0x0008 ) {
		return NULL ;
	}

	iphdr = (IPHdr*) ( (char*)datahdr + sizeof( DataHdr ) );

	return &iphdr->ip_dst ;
}

unsigned short int
get_dat_srcport ( MacHdr *mp )
{
	DataHdr *datahdr ;
	IPHdr *iphdr ;
	UDPHdr *udphdr ;
	TCPHdr *tcphdr ;
	unsigned short int res_port = -1;


	if ( COOK_FRAME_TYPE(mp->frm_ctrl) != DATA_FRAME )
		return res_port ;

	if ( is_unofficial_datfrm(mp ) )
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
	else {
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) - 6 )  ;
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
		}
	}

	// is IP protocol ?
	if ( datahdr->proto_id != 0x0008 ) { 
		return res_port ;
	}

	iphdr = (IPHdr*) ( (char*)datahdr + sizeof( DataHdr ) );

	switch ( iphdr->ip_proto) 
	{
		case IPPROTO_UDP :
			udphdr = (UDPHdr *) ((char*)iphdr + sizeof( IPHdr)) ;
			res_port = udphdr->uh_sport ;
			break;

		case IPPROTO_TCP:
			tcphdr = (TCPHdr *) ((char*)iphdr + sizeof( IPHdr) );
			res_port = tcphdr->th_sport ;
			break;

		default:
			return res_port;
	}
	return res_port ;

}

unsigned short int
get_dat_dstport ( MacHdr *mp )
{
	DataHdr *datahdr ;
	IPHdr *iphdr ;
	UDPHdr *udphdr ;
	TCPHdr *tcphdr ;
	unsigned short int res_port = -1;


	if ( COOK_FRAME_TYPE(mp->frm_ctrl) != DATA_FRAME )
		return res_port ;

	if ( is_unofficial_datfrm(mp ) )
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
	else {
		datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) - 6 )  ;
		if ( mp->frm_ctrl & FCFLG_TODS && mp->frm_ctrl & FCFLG_FROMDS ) {
			datahdr = (DataHdr*) ((char*)mp + sizeof( MacHdr) )  ;
		}
	}

	// is ip protocol ?
	if ( datahdr->proto_id != 0x0008 ) { 
		return res_port ;
	}

	iphdr = (IPHdr*) ( (char*)datahdr + sizeof( DataHdr ) );

	switch ( iphdr->ip_proto) {
		case IPPROTO_UDP :
			udphdr = (UDPHdr *) ((char*)iphdr + sizeof( IPHdr)) ;
			res_port = udphdr->uh_dport ;
			break;
		case IPPROTO_TCP:
			tcphdr = (TCPHdr *) ((char*)iphdr + sizeof( IPHdr)) ;
			res_port = tcphdr->th_dport ;
			break;
		default:
			return res_port;
	}
	return res_port ;
}



// get start point of management fixed value and variable value
// it also returns last length of element at "lastlen"( 3rd argument)
char * 
get_mgt_vstart( MacHdr *mp, int len, int *lastlen ) 
{
	char *tagp ;
	int tmplen ;

	tagp = ( (char*)mp + sizeof(MacHdr) - 6 ) ;
	tmplen = len - ( sizeof(MacHdr) -6 );

	switch( mp->frm_ctrl & 0x00ff ) {
		case MGT_ASSOC_REQ: 
			*lastlen = tmplen - ( 2 + 2) ;
			return ( tagp + 2 + 2 );
		case MGT_ASSOC_RESP:
			*lastlen = tmplen - ( 2 + 2 + 2) ;
			return ( tagp + 2 + 2 + 2 );
		case MGT_REASSOC_REQ:
			*lastlen = tmplen - ( 2 + 2 + 6) ;
			return ( tagp + 2 + 2 + 6 );
		case MGT_REASSOC_RESP:
			*lastlen = tmplen - ( 2 + 2 + 2) ;
			return ( tagp + 2 + 2 + 2 );
		case MGT_PROBE_REQ:
			*lastlen = tmplen ;
			return ( tagp ) ;
		case MGT_PROBE_RESP:
			*lastlen = tmplen - ( 8 + 2 + 2) ;
			return ( tagp + 8 + 2 + 2 );
		case MGT_BEACON:
			*lastlen = tmplen - ( 8 + 2 + 2) ;
			return ( tagp + 8 + 2 + 2 ) ;
		case MGT_ATIM:
			*lastlen = tmplen ;
			return NULL;
		case MGT_DISASS:
			*lastlen = tmplen ;
			return NULL;
		case MGT_AUTHENTICATION:
			*lastlen = tmplen - ( 2 + 2 + 2) ;
			return ( tagp + 2 + 2 + 2 );
		case MGT_DEAUTHENTICATION:
			*lastlen = tmplen ;
			return NULL;
	}
	return NULL;
}

char * 
get_mgt_fstart( MacHdr *mp, int len) 
{
	char *tagp ;
	tagp = ( (char*)mp + sizeof(MacHdr) - 6 ) ;

	return tagp;
}



char *
get_mgt_fvalue( MacHdr *mp,  int len , int fixed_id ) 
{
	char *current_fv_start, *fvp = NULL ;
	unsigned short int current_frmctrl ;


	current_frmctrl = get_frmtype( mp ) ;
	current_fv_start= get_mgt_fstart( mp, len );
	
	switch( fixed_id ) { 
		// authetication number
		case AUTHNUM:
			if ( current_frmctrl == MGT_AUTHENTICATION ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			break;

		// authentication sequence 
		case AUTHSEQ:
			if ( current_frmctrl == MGT_AUTHENTICATION ) {
				fvp = current_fv_start + SIZE_AUTHNUM ;
				return fvp ;
			}
			break;

		// beacon interval
		case BEACONINTERVAL:
			if ( current_frmctrl == MGT_BEACON ) {
				fvp = current_fv_start + SIZE_TIMESTAMP ;
				return fvp ;
			}

			if ( current_frmctrl == MGT_PROBE_REQ ) {
				fvp = current_fv_start + SIZE_TIMESTAMP ;
				return fvp ;
			}
			break;

		// capability
		case CAPABILITY:
			if ( current_frmctrl == MGT_BEACON ) {
				fvp = current_fv_start + SIZE_TIMESTAMP + SIZE_BEACONINTERVAL ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_ASSOC_REQ ){
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_ASSOC_RESP ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_REASSOC_REQ ){
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_REASSOC_RESP ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_PROBE_RESP ) {
				fvp = current_fv_start + SIZE_TIMESTAMP + SIZE_BEACONINTERVAL ;
				return fvp ;
			}

			break;

		// current ap field
		case CURRENTAP:
			if ( current_frmctrl == MGT_REASSOC_REQ ) {
				fvp = current_fv_start + SIZE_CAPABILITY + SIZE_LISTENINTERVAL ;
				return fvp ;
			}
			break;

		// listen interval
		case LISTENINTERVAL:
			if ( current_frmctrl == MGT_ASSOC_REQ ) {
				fvp = current_fv_start + SIZE_CAPABILITY  ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_REASSOC_REQ ) {
				fvp = current_fv_start + SIZE_CAPABILITY  ;
				return fvp ;
			}
			break;

		// reason code
		case REASONCODE:
			if ( current_frmctrl == MGT_DISASS ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}

			if ( current_frmctrl == MGT_DEAUTHENTICATION ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			break;

		// assoc id
		case ASSOCID:
			if ( current_frmctrl == MGT_ASSOC_RESP ) {
				fvp = current_fv_start + SIZE_CAPABILITY + SIZE_STATUSCODE ;
				return fvp ;
			}

			if ( current_frmctrl == MGT_REASSOC_RESP ) {
				fvp = current_fv_start + SIZE_CAPABILITY + SIZE_STATUSCODE ;
				return fvp ;
			}
			break;

		// status code
		case STATUSCODE:
			if ( current_frmctrl == MGT_ASSOC_RESP ) {
				fvp = current_fv_start + SIZE_CAPABILITY ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_REASSOC_RESP ) {
				fvp = current_fv_start + SIZE_CAPABILITY ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_AUTHENTICATION )  {
				fvp = current_fv_start + SIZE_AUTHNUM + SIZE_AUTHSEQ ;
				return fvp ;
			}
			break;


		// timestamp
		case TIMESTAMP:
			if ( current_frmctrl == MGT_BEACON ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}
			if ( current_frmctrl == MGT_PROBE_RESP ) {
				fvp = current_fv_start + 0 ;
				return fvp ;
			}

			break;

		default:
			break;
	}

	return NULL;
}


int
get_mgt_vvalue( MacHdr *mp , int len, int element_id, Mgt_Element *e_ptr  ) 
{ 
	char * start_ptr ;
	char *tmp_ptr ;
	int lastlen ;
	int count ;

	start_ptr = get_mgt_vstart( mp, len, &lastlen ) ;
	if ( start_ptr == NULL ) 
		return FALSE ;

	tmp_ptr = start_ptr ;
	count = 0 ;

	while( count < lastlen ) {
		if ( tmp_ptr[0] == element_id && tmp_ptr[1] != 0) {
				e_ptr->eid = tmp_ptr[0] ;
				e_ptr->len = tmp_ptr[1] ; 
				e_ptr->ptr = &tmp_ptr[2] ;
			return TRUE;
		} else // consume and search elements
		{
			count = count + (int)tmp_ptr[1] + 2;
			tmp_ptr = (char*)(tmp_ptr + tmp_ptr[1] +2) ;
		}

	}

	return FALSE ;
}


