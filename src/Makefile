#
# Garuda Makefile
#
CC = gcc
YACC = bison
LEX = flex

OBJS = cio.o init.o fetch.o chkfrm.o detect.o filter.o statistics.o \
       log.o session.o wpktapi.o member.o chkspoof.o mysql.o
RULE_OBJS = ruleyacc.o rulelex.o setapi.o symnum.o 
CONF_OBJS = confyacc.o conflex.o 
#OPTIMIZEFLAGS = -O2
#ETCFLAGS = -pipe 
#CFLAGS = -ggdb -Wall -fPIC $(OPTIMIZEFLAGS) $(ETCFLAGS)
CFLAGS = -ggdb -Wall 
CURRENTDIR = .
INC = -I. -I. -I..
# DEFINES options : PRISM, DEBUGZ
#  * PRISM  : if you have intersil type wireless card, define it
#  * DEBUGZ : Debugging message output for developer
#                       
#
#DEFINES = -DPRISM -DDEBUGZ 
DEFINES = -D_GNU_SOURCE -DGARUDA_LINUX -DLOVE_FROG  -DUNOFICIAL_DEVICE
LIBS =  -lfl -lpcap -lmysqlclient -L/usr/lib/mysql

.c.o:
	$(CC) -c $< $(DEFINES) $(CFLAGS) $(INC) 

all: Build_conf Build_rule  $(OBJS) 
	$(CC) -o garuda garuda.c $(DEFINES) $(CFLAGS)  $(INC) $(OBJS) \
	$(RULE_OBJS) $(CONF_OBJS) $(LIBS) 

Build_conf: confyacc.c conflex.c $(CONF_OBJS)

confyacc.c:
	$(YACC) -o confyacc.c -p conf_yy -d conf.y
conflex.c:
	$(LEX) -oconflex.c -Pconf_yy conf.l 

Build_rule: ruleyacc.c rulelex.c $(RULE_OBJS)

ruleyacc.c:
	$(YACC) -o ruleyacc.c -d rule.y 
rulelex.c:
	$(LEX) -orulelex.c  rule.l  


clean:
	rm -rf *.o garuda 
	rm -rf rulelex.c ruleyacc.c ruleyacc.h
	rm -rf conflex.c confyacc.c confyacc.h



