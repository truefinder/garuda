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
/* $Id: chkfrm.h,v 1.1.1.1 2004/06/03 14:10:33 seunghyun Exp $ */

/* chkfrm.h */
#ifndef CHEKER
#define CHEKER

/* check functions */

int chk_type              (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_todsflg           (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_fromdsflg         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_morefragflg       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_retryflg          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_pwrmgtflg         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_moredatflg        (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_wepflg            (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_orderflg          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_duration          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_addr1             (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_addr2             (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_addr3             (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_seq               (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_addr4             (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_authnum       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_authseq       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_beaconinterval(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_capability    (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_currentap     (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_listeninterval(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_reasoncode    (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_associd       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_statuscode    (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_timestamp     (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_ssid          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_supportedrates(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_fhparam       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_dsparam       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_cfparam       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_ibssparam     (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_tim           (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgt_challenge     (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_dsap          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ssap          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ctrl          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_orgcode       (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_proto         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_proto      (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_srcip      (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_dstip      (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_tcp_srcport(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_tcp_dstport(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_udp_srcport(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_dat_ip_udp_dstport(MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_mgtfprint         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_datfprint         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_ctrlfprint        (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_ipfprint          (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_tcpfprint         (MacHdr *mp, Rule_Entry *rp, int len)   ;
int chk_udpfprint         (MacHdr *mp, Rule_Entry *rp, int len)   ;


#endif



