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
/* $Id: symnum.c,v 1.2 2004/06/23 09:14:18 seunghyun Exp $ */

/****************************************************************************
  *
  * symnum.c
  *
  * this module inquires rule fields name , returns each definition number
  * to caller
  *
  *
  ***************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpacket.h"
#include "symnum.h"
#include "config.h"


// use in ruleyacc.c
VarList vRuleList[64] = {
        { "Id"                      , CHK_ID                      },
        { "Count"                   , CHK_COUNT                   },
        { "Risk"                    , CHK_RISK                    },
        { "Timer"                   , CHK_TIMER                   },
        { "Desc"                    , CHK_DESC                    },
	{ "Pkt.type"                , CHK_PKT_TYPE                },
	{ "Pkt.todsflg"             , CHK_PKT_TODSFLG             },
	{ "Pkt.fromdsflg"           , CHK_PKT_FROMDSFLG           },
	{ "Pkt.morefragflg"         , CHK_PKT_MOREFRAGFLG         },
	{ "Pkt.retryflg"            , CHK_PKT_RETRYFLG            },
	{ "Pkt.pwrmgtflg"           , CHK_PKT_PWRMGTFLG           },
	{ "Pkt.moredatflg"          , CHK_PKT_MOREDATFLG          },
	{ "Pkt.wepflg"              , CHK_PKT_WEPFLG              },
	{ "Pkt.orderflg"            , CHK_PKT_ORDERFLG            },
	{ "Pkt.duration"            , CHK_PKT_DURATION            },
	{ "Pkt.addr1"               , CHK_PKT_ADDR1               },
	{ "Pkt.addr2"               , CHK_PKT_ADDR2               },
	{ "Pkt.addr3"               , CHK_PKT_ADDR3               },
	{ "Pkt.seq"                 , CHK_PKT_SEQ                 },
	{ "Pkt.addr4"               , CHK_PKT_ADDR4               },
	{ "Pkt.mgt.authnum"         , CHK_PKT_MGT_AUTHNUM         },
	{ "Pkt.mgt.authseq"         , CHK_PKT_MGT_AUTHSEQ         },
	{ "Pkt.mgt.beaconinterval"  , CHK_PKT_MGT_BEACONINTERVAL  },
	{ "Pkt.mgt.capability"      , CHK_PKT_MGT_CAPABILITY      },
	{ "Pkt.mgt.currentap"       , CHK_PKT_MGT_CURRENTAP       },
	{ "Pkt.mgt.listeninterval"  , CHK_PKT_MGT_LISTENINTERVAL  },
	{ "Pkt.mgt.reasoncode"      , CHK_PKT_MGT_REASONCODE      },
	{ "Pkt.mgt.associd"         , CHK_PKT_MGT_ASSOCID         },
	{ "Pkt.mgt.statuscode"      , CHK_PKT_MGT_STATUSCODE      },
	{ "Pkt.mgt.timestamp"       , CHK_PKT_MGT_TIMESTAMP       },
	{ "Pkt.mgt.ssid"            , CHK_PKT_MGT_SSID            },
	{ "Pkt.mgt.supportedrates"  , CHK_PKT_MGT_SUPPORTEDRATES  },
	{ "Pkt.mgt.fhparam"         , CHK_PKT_MGT_FHPARAM         },
	{ "Pkt.mgt.dsparam"         , CHK_PKT_MGT_DSPARAM         },
	{ "Pkt.mgt.cfparam"         , CHK_PKT_MGT_CFPARAM         },
	{ "Pkt.mgt.ibssparam"       , CHK_PKT_MGT_IBSSPARAM       },
	{ "Pkt.mgt.tim"             , CHK_PKT_MGT_TIM             },
	{ "Pkt.mgt.challenge"       , CHK_PKT_MGT_CHALLENGE       },
	{ "Pkt.dat.dsap"            , CHK_PKT_DAT_DSAP            },
	{ "Pkt.dat.ssap"            , CHK_PKT_DAT_SSAP            },
	{ "Pkt.dat.ctrl"            , CHK_PKT_DAT_CTRL            },
	{ "Pkt.dat.orgcode"         , CHK_PKT_DAT_ORGCODE         },
	{ "Pkt.dat.proto"           , CHK_PKT_DAT_PROTO           },
	{ "Pkt.dat.ip.proto"        , CHK_PKT_DAT_IP_PROTO        },
	{ "Pkt.dat.ip.srcip"        , CHK_PKT_DAT_IP_SRCIP        },
	{ "Pkt.dat.ip.dstip"        , CHK_PKT_DAT_IP_DSTIP        },
	{ "Pkt.dat.ip.tcp.srcport"  , CHK_PKT_DAT_IP_TCP_SRCPORT  },
	{ "Pkt.dat.ip.tcp.dstport"  , CHK_PKT_DAT_IP_TCP_DSTPORT  },
	{ "Pkt.dat.ip.udp.srcport"  , CHK_PKT_DAT_IP_UDP_SRCPORT  },
	{ "Pkt.dat.ip.udp.srcport"  , CHK_PKT_DAT_IP_UDP_SRCPORT  },
	{ "Pkt.mgtfprint"           , CHK_PKT_MGTFPRINT           },
	{ "Pkt.datfprint"           , CHK_PKT_DATFPRINT           },
	{ "Pkt.ctrlfprint"          , CHK_PKT_CTRLFPRINT          },
	{ "Pkt.ipfprint"            , CHK_PKT_IPFPRINT            },
	{ "Pkt.tcpfprint"           , CHK_PKT_TCPFPRINT           },
	{ "Pkt.udpfprint"           , CHK_PKT_UDPFPRINT           },
	{ ""				, -1 			}
};


// use in confyacc.c
VarList vConfList[16] = {
	{"ServerName"		, CNF_SERVERNAME      },
	{"GarudaRoot"      	, CNF_GARUDAROOT      },
	{"DeviceName"      	, CNF_DEVICENAME      },
	{"DeamonMode"      	, CNF_DEAMONMODE      },
	{"SimulationMode"  	, CNF_SIMULATIONMODE  },
	{"LogDirectory"    	, CNF_LOGDIRECTORY    },
	{"FilterFile"      	, CNF_FILTERFILE      },
	{"RuleFile"        	, CNF_RULEFILE        },
	{"SampleFile"      	, CNF_SAMPLEFILE      },
	{"TrustAPList"		, CNF_TRUSTAPLIST     },
	{"MysqlUse"		, CNF_MYSQLUSE        },
	{"MysqlHost"		, CNF_MYSQLHOST       },
	{"MysqlUser"		, CNF_MYSQLUSER       },
	{"MysqlPass"		, CNF_MYSQLPASS       },
	{""			, -1		      }
};


int
GetFieldID( char * varname ) 
{
	int i =0 ;
	while (1 ) {
		// var name does not found 
		if ( vRuleList[i].nid == -1 )  
			return -1;
		// var name found !!!  return code ;
		if ( ! strcmp( varname, vRuleList[i].varname ) ) {
			return vRuleList[i].nid ;
		}
		i++;
	}
	return -1 ;
}


int
GetConfigFieldId ( char * varname ) 
{
	int i =0 ;
	while (1 ) {
		// not found
		if ( vConfList[i].nid == -1 )   
			return -1; 

		// found
		if ( ! strcmp( varname, vConfList[i].varname ) ) {
			return vConfList[i].nid ;
		}
		i++;
	}

	return -1 ;
}

