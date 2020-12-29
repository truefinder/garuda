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
/* $Id: rule.h,v 1.1.1.1 2004/06/03 14:10:34 seunghyun Exp $ */
/* rule.h 
   *
   *
   *
   */
#ifndef _RULE_H
#define _RULE_H

#define RTYPE_NONE	0
#define RTYPE_MATCH	1
#define RTYPE_COUNT	2
#define RTYPE_STATUS	3

// internal rule setting 1~ 100
// user defined rule set must start at 101
#define IRN_NULLPROBE	1
#define IRN_NULLASSOC	2
#define IRN_MACSPOOF	3
#define IRN_ROGUEAP	4


#endif
