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
/* $Id: decode.c,v 1.1.1.1 2004/06/03 14:10:33 seunghyun Exp $ */
/* decode.c */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "cio.h"
#include "wpacket.h"
#include "decode.h"
#include "debug.h"


#define COOK_FRAME_TYPE(x)    (((x) & 0xC) >> 2)
#define MGT_FRAME            0x00       /* Frame type is management */
#define CONTROL_FRAME        0x01       /* Frame type is control */
#define DATA_FRAME           0x02       /* Frame type is Data */

#define COOK_FRAME_SUBTYPE(x)	(((x) & 0xF0) >> 4)
#define MGT_ASSOC_REQ        0x00       /* Management - association request        */
#define MGT_ASSOC_RESP       0x01       /* Management - association response       */
#define MGT_REASSOC_REQ      0x02       /* Management - reassociation request      */
#define MGT_REASSOC_RESP     0x03       /* Management - reassociation response     */
#define MGT_PROBE_REQ        0x04       /* Management - Probe request              */
#define MGT_PROBE_RESP       0x05       /* Management - Probe response             */
#define MGT_BEACON           0x08       /* Management - Beacon frame               */
#define MGT_ATIM             0x09       /* Management - ATIM                       */
#define MGT_DISASS           0x0A       /* Management - Disassociation             */
#define MGT_AUTHENTICATION   0x0B       /* Management - Authentication             */
#define MGT_DEAUTHENTICATION 0x0C       /* Management - Deauthentication           */
#define CTRL_PS_POLL         0x1A       /* Control - power-save poll               */
#define CTRL_RTS             0x1B       /* Control - request to send               */
#define CTRL_CTS             0x1C       /* Control - clear to send                 */
#define CTRL_ACKNOWLEDGEMENT 0x1D       /* Control - acknowledgement               */
#define CTRL_CFP_END         0x1E       /* Control - contention-free period end    */
#define CTRL_CFP_ENDACK      0x1F       /* Control - contention-free period end/ack */
#define DATA                 0x20       /* Data - Data                             */
#define DATA_CF_ACK          0x21       /* Data - Data + CF acknowledge            */
#define DATA_CF_POLL         0x22       /* Data - Data + CF poll                   */
#define DATA_CF_ACK_POLL     0x23       /* Data - Data + CF acknowledge + CF poll  */
#define DATA_NULL_FUNCTION   0x24       /* Data - Null function (no data)          */
#define DATA_CF_ACK_NOD      0x25       /* Data - CF ack (no data)                 */
#define DATA_CF_POLL_NOD     0x26       /* Data - Data + CF poll (No data)         */
#define DATA_CF_ACK_POLL_NOD 0x27       /* Data - CF ack + CF poll (no data)       */

/* let's cooke fame's ds bits */
#define COOK_FRAME_DSBITS(x)	(((x) & 0x00C0 ) >> 6 )
#define DS_NOTHING	0x00
#define DS_FROM_ONLY	0x01
#define DS_TO_ONLY	0x02
#define DS_BOTH		0x03


/* Limit to addrX  by frog */
#define LT_ADDR1		1000
#define LT_ADDR2		2000
#define LT_ADDR3		3000
#define LT_ADDR4		4000

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24       /* Length of Managment frame-headers */

/* Frame type/subype combinations with version = 0 */
/*** FRAME TYPE *****  HEX ****  SUBTYPE TYPE  DESCRIPT ********/
#define WLAN_TYPE_MGMT_ASREQ   0x0      /* 0000    00  Association Req */
#define WLAN_TYPE_MGMT_ASRES   0x10     /* 0001    00  Assocaition Res */
#define WLAN_TYPE_MGMT_REREQ   0x20     /* 0010    00  Reassoc. Req.   */
#define WLAN_TYPE_MGMT_RERES   0x30     /* 0011    00  Reassoc. Resp.  */
#define WLAN_TYPE_MGMT_PRREQ   0x40     /* 0100    00  Probe Request   */
#define WLAN_TYPE_MGMT_PRRES   0x50     /* 0101    00  Probe Response  */
#define WLAN_TYPE_MGMT_BEACON  0x80     /* 1000    00  Beacon          */
#define WLAN_TYPE_MGMT_ATIM    0x90     /* 1001    00  ATIM message    */
#define WLAN_TYPE_MGMT_DIS     0xa0     /* 1010    00  Disassociation  */
#define WLAN_TYPE_MGMT_AUTH    0xb0     /* 1011    00  Authentication  */
#define WLAN_TYPE_MGMT_DEAUTH  0xc0     /* 1100    00  Deauthentication*/

#define WLAN_TYPE_CONT_PS      0xa4     /* 1010    01  Power Save      */
#define WLAN_TYPE_CONT_RTS     0xb4     /* 1011    01  Request to send */
#define WLAN_TYPE_CONT_CTS     0xc4     /* 1100    01  Clear to sene   */
#define WLAN_TYPE_CONT_ACK     0xd4     /* 1101    01  Acknowledgement */
#define WLAN_TYPE_CONT_CFE     0xe4     /* 1110    01  Cont. Free end  */
#define WLAN_TYPE_CONT_CFACK   0xf4     /* 1111    01  CF-End + CF-Ack */

#define WLAN_TYPE_DATA_DATA    0x08     /* 0000    10  Data            */
#define WLAN_TYPE_DATA_DTCFACK 0x18     /* 0001    10  Data + CF-Ack   */
#define WLAN_TYPE_DATA_DTCFPL  0x28     /* 0010    10  Data + CF-Poll  */
#define WLAN_TYPE_DATA_DTACKPL 0x38     /* 0011    10  Data+CF-Ack+CF-Pl */
#define WLAN_TYPE_DATA_NULL    0x48     /* 0100    10  Null (no data)  */
#define WLAN_TYPE_DATA_CFACK   0x58     /* 0101    10  CF-Ack (no data)*/
#define WLAN_TYPE_DATA_CFPL    0x68     /* 0110    10  CF-Poll (no data)*/
#define WLAN_TYPE_DATA_ACKPL   0x78     /* 0111    10  CF-Ack+CF-Poll  */

/*** Flags for IEEE 802.11 Frame Control ***/
/* The following are designed to be bitwise-AND-d in an 8-bit u_char */
#define WLAN_FLAG_TODS      0x0100    /* To DS Flag   10000000 */
#define WLAN_FLAG_FROMDS    0x0200    /* From DS Flag 01000000 */
#define WLAN_FLAG_FRAG      0x0400    /* More Frag    00100000 */
#define WLAN_FLAG_RETRY     0x0800    /* Retry Flag   00010000 */
#define WLAN_FLAG_PWRMGMT   0x1000    /* Power Mgmt.  00001000 */
#define WLAN_FLAG_MOREDAT   0x2000    /* More Data    00000100 */
#define WLAN_FLAG_WEP       0x4000    /* Wep Enabled  00000010 */
#define WLAN_FLAG_ORDER     0x8000    /* Strict Order 00000001 */



/* show_wlanpkt() decodes packets and print stdout
 * but if DEBUGZ unset, it will be not apeared 
 */ 
void 
show_wlanpkt( const u_char * pkt_data, int len )
{
#ifdef PRISM
	// ORINOCO
	Prism_header *prism_hdr ;
	Mac_header *mac_hdr ;
	int mgthlen , datahlen, ctrlhlen ;
#else 
	// CISCO
	Mac_header *mac_hdr ;
	int mgthlen , datahlen, ctrlhlen ;
#endif


#ifdef PRISM
	// ORINOCO
	prism_hdr = ( Prism_header *) pkt_data ;
	mac_hdr = ( Mac_header  * ) (pkt_data + sizeof(Prism_header )) ;
#else
	// CISCO
	mac_hdr = ( Mac_header  * ) (pkt_data ) ;
#endif

	Coutn("");
	Coutn("IEEE 802.11 MAC header dump");
	Cdumphex( (char*)mac_hdr, 24 ); /* dump 802.11b header */
	Coutn("");

	switch ( COOK_FRAME_TYPE(mac_hdr->frame_control) ){ 
		
		// level1 Setting Frame type  : management frame
		/* Management packet */
		// ctrl, duration, addr1, addr2, addr3, seq 
		// + fixed param
		// + taged param
		// but we will dump it according to capture length

		case MGT_FRAME:
			mgthlen=0;
			Cout("Management frame!!!!! " );

			//mgthlen = ( sizeof( Prism_header) + sizeof(Mac_header) -6) ;
			mgthlen = ( sizeof(Mac_header) -6) ;
			do {
				switch( COOK_FRAME_SUBTYPE( mac_hdr->frame_control) ) {
					case MGT_ASSOC_REQ :	
						/* Management - association request        */
						Coutn("assoc req");
						break;
					case MGT_ASSOC_RESP:     
					      	/* Management - association response       */ 
						Coutn("assoc resp");
						break;
					case MGT_REASSOC_REQ:  
					     	/* Management - reassociation request      */ 
						Coutn("reassoc req ");
						break;
					case MGT_REASSOC_RESP:     
						/* Management - reassociation response     */ 
						Coutn("reassoc resp");
						break;
					case MGT_PROBE_REQ:    
						/* Management - Probe request              */ 
						Coutn("probe req");
						break;
					case MGT_PROBE_RESP:       
						/* Management - Probe response             */ 
						Coutn("probe resp");
						break ;
					case MGT_BEACON:           
						/* Management - Beacon frame               */ 
						Coutn("beacon");
						break;
					case MGT_ATIM:         
						/* Management - ATIM                       */ 
					       Coutn("atim");	
						break;
					case MGT_DISASS:     
						/* Management - Disassociation             */ 
						Coutn("disass");	
						break;
					case MGT_AUTHENTICATION:
						/* Management - Authentication             */ 
						Coutn("auth");	
						break;
					case MGT_DEAUTHENTICATION: 
						/* Management - Deauthentication           */ 
						Coutn("deauth");
						break;

					default:
						Coutn("Unknown type");
						break;
				}
			} while(0);
			show_machdr( (char*)mac_hdr, LT_ADDR3) ;
			show_lastdump( (char*)(pkt_data + mgthlen), len - mgthlen  ) ;
			Coutn("");
			Coutn("** if possible, it could be dissected ***");
			show_mgtfrm( (char*)(pkt_data + mgthlen), COOK_FRAME_SUBTYPE(mac_hdr->frame_control ), len-mgthlen) ;

			break;

		// level1 Setting Frame type  : control frame
		/* Control pakcet */
		// subtype :
		//	1010 ctrl,duration, addr1, addr2
		//	1011 ctrl,duration, addr1, addr2
		// 1100,1101 ctrl,duration, addr1
		// 1110,1111 ctrl,duration, addr1, addr2
		case CONTROL_FRAME:
			ctrlhlen=0;
			Cout("Control frame!!!!! ");
			do {
				switch( COOK_FRAME_SUBTYPE( mac_hdr->frame_control) ) { 
					case CTRL_PS_POLL:
						Coutn("ctrl ps poll "); // addr2
						show_machdr( (char*)mac_hdr, LT_ADDR2) ;
						break;
					case CTRL_RTS:
						Coutn("ctrl rts "); // addr2
						show_machdr( (char*)mac_hdr, LT_ADDR2) ;
						break;
					case CTRL_CTS:
						Coutn("ctrl cts "); //addr1
						show_machdr( (char*)mac_hdr, LT_ADDR1) ;
						break;
					case CTRL_ACKNOWLEDGEMENT:
						Coutn("ctrl ack "); //addr1
						show_machdr( (char*)mac_hdr, LT_ADDR1) ;
						break;
					case CTRL_CFP_END:
						Coutn("ctrl cfp end "); // addr2
						show_machdr( (char*)mac_hdr, LT_ADDR2) ;
						break;
					case CTRL_CFP_ENDACK:
						Coutn("ctrl cfp end ack"); //addr2
						show_machdr( (char*)mac_hdr, LT_ADDR2) ;
						break;

					default:
						break;
				}
			}while(0);
			break;

		// level1 Setting Frame type  : data frame
		/* Data packet */ // tods,fromds 
		//	 0 0 ctrl,duration, addr1, addr2, addr3
		//	 0 1 ctrl,duration, addr1, addr2, addr3
		//	 1 0 ctrl,duration, addr1, addr2, addr3
		//	 1 1 ctrl,duration, addr1, addr2, addr3, addr4
		case DATA_FRAME: 
			datahlen = 0;
			Cout("Data frame !!!!! ");
			//datahlen = sizeof(Prism_header) + sizeof(Mac_header) - 6;
			datahlen = sizeof(Mac_header) - 6;

			do {
				switch( COOK_FRAME_DSBITS( mac_hdr->frame_control) ) { 
					case DS_NOTHING	:
						Coutn("ds nothing");
						show_machdr( (char*)mac_hdr, LT_ADDR3) ;
						show_datafrm( (char*)(pkt_data + datahlen) , len - datahlen );
						break;
					case DS_FROM_ONLY:
						Coutn("ds from only");
						show_machdr( (char*)mac_hdr, LT_ADDR3) ;
						show_datafrm( (char*)(pkt_data + datahlen), len -datahlen );
						break; 
					case DS_TO_ONLY:
						Coutn("ds to only");
						show_machdr( (char*)mac_hdr, LT_ADDR3) ;
						show_datafrm( (char*)(pkt_data + datahlen) , len-datahlen );
						break; 
					case DS_BOTH: // it especialy uses mac4 field
						Coutn("ds both ");
						show_machdr( (char*)mac_hdr, LT_ADDR4) ;
						show_datafrm( (char*)(pkt_data + (datahlen + 6)), len-(datahlen+6) );
						break;
					default:
						break;
				}
			}while(0);
			break;

		default:
			Coutn("Unknown frame !!!!!");
			break;
	}

	Coutn("");

	return ;
}

void 
show_machdr ( const u_char *macpkt , int type) 
{
	Mac_header *mac_hdr ;
	mac_hdr = ( Mac_header  * ) (macpkt ) ;

	switch( type ) {
		case LT_ADDR1:
			printf("duration_id : %d\n", (unsigned short int ) mac_hdr->duration_id );
			Cout("mac1 : "); Cdumphex( (char *) mac_hdr->mac1, 6 ); Coutn("");
			break;

		case LT_ADDR2:
			printf("duration_id : %d\n", (unsigned short int ) mac_hdr->duration_id );
			Cout("mac1 : "); Cdumphex( (char *) mac_hdr->mac1, 6 ); Coutn("");
			Cout("mac2 : "); Cdumphex( (char *) mac_hdr->mac2, 6 ); Coutn("");
			break;

		case LT_ADDR3:
			printf("duration_id : %d\n", (unsigned short int ) mac_hdr->duration_id );
			Cout("mac1 : "); Cdumphex( (char *) mac_hdr->mac1, 6 ); Coutn("");
			Cout("mac2 : "); Cdumphex( (char *) mac_hdr->mac2, 6 ); Coutn("");
			Cout("mac3 : "); Cdumphex( (char *) mac_hdr->mac3, 6 ); Coutn("");
			printf("sequence : %d\n", (unsigned short int ) mac_hdr->sequence );
			break;

		case LT_ADDR4:
			printf("duration_id : %d\n", (unsigned short int ) mac_hdr->duration_id );
			Cout("mac1 : "); Cdumphex( (char *) mac_hdr->mac1, 6 ); Coutn("");
			Cout("mac2 : "); Cdumphex( (char *) mac_hdr->mac2, 6 ); Coutn("");
			Cout("mac3 : "); Cdumphex( (char *) mac_hdr->mac3, 6 ); Coutn("");
			printf("sequence : %d\n", (unsigned short int ) mac_hdr->sequence );
			Cout("mac4 : "); Cdumphex( (char *) mac_hdr->mac4, 6 ); Coutn("");
			break;
		default:
			break;
	}

	return ;
}

void 
show_datafrm( const  u_char *datapkt, int nlast )
{
	EthLlc *llc ;
	EthLlcOther *llcother ;
	char *dumpdata ;

	llc = ( EthLlc *) datapkt ;
	llcother = ( EthLlcOther *) ( datapkt + sizeof(EthLlc) );
	dumpdata = (char*) ( datapkt + sizeof(EthLlc) + sizeof( EthLlcOther) );

	Coutn("LLC header dump : ");
	Cdumphex( (char*) llc , 8); Coutn("");
	Coutn("LLC header :");
	printf(" DSAP: %X, SSAP: %X\n", llc->dsap, llc->ssap );

	//Cout("llc dump "); Cdumphex( (char*)llcother, 6 );
	Coutn("LLC Other : ");
	printf("control: %#x " ,llcother->ctrl); 
	Coutn("");
	Cout("org_code: " ); Cdumphex( (char*)llcother->org_code , 3 ); Coutn("");
	Cout("proto id :");  printf("%#04hx", ntohs( (uint16_t)llcother->proto_id) ); Coutn("");

	// put the cap which is ip header or ethernet protocols 
	Cdumphex( (char*)dumpdata, nlast );

	return ;

}

void 
show_lastdump( const u_char *dump, int len ) 
{
	Cdumphex( (char *) dump, len );
	return ;
}



void 
show_mgtfrm( const u_char *mgtpkt, int type, int nlast )
{
	switch( type ) 
	{
		case MGT_ASSOC_REQ :	
			break;
		case MGT_ASSOC_RESP:     
			break;
		case MGT_REASSOC_REQ:  
			break;
		case MGT_REASSOC_RESP:     
			break;
		case MGT_PROBE_REQ:    
			break;
		case MGT_PROBE_RESP:       
			break ;
		case MGT_BEACON:  // especailly dump essid
			// fixed parameter 12bytes
			Cout( "Timestamp: "); Cdumphex( (char*)mgtpkt, 8 );
			Cout(" Interval : "); Cdumphex( (char *)mgtpkt+8, 2 );
			Cout(" Cap info : " ); Cdumphex( (char*)mgtpkt+10, 2 );
			// tagged parameter ? bytes 
			// Cdumpchar( (char*)mgtpkt+12, nlast-12);
			show_tagparam( (char*)mgtpkt+12 );
			
			break;
		case MGT_ATIM:         
			break;
		case MGT_DISASS:     
			break;
		case MGT_AUTHENTICATION:
			break;
		case MGT_DEAUTHENTICATION: 
			break;
		default:
			break;
	}
	return ;
}


/* Decoding tagged parameter in management frame */
void 
show_tagparam ( const u_char *tagpkt )
{
	int i=0 , n ; 
	int stat=1 ; 
	int desc[4] ;
	char *str;
       
	str=(char*) tagpkt ;

	Coutn("");
	while( stat-- ) {
	       	desc[i] = str[i] ;  printf("desc : %d, ", desc[i] ); i++;  
		n = str[i]  ; printf("len : %hx, ", n);  i++;
		printf("interpretation: ");
		while(n--) {
			if (isprint( str[i] )) 
				printf("%c ", str[i] );
			else printf("0x%hhx ", str[i] );
		       	i++;
		}
		printf("\n");
	}


}

