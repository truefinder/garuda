#!/bin/sh

### Check if this variables are properly adapted
### device name : it could be both "eth1" and "wifi0"
DEVNAME="eth1"

### Base directory setting
### need not to set by user, default setting is also good to work.
GARUDA_DIR=`pwd`
ETC_DIR="$GARUDA_DIR/etc"
SBIN_DIR="$GARUDA_DIR/sbin"
BIN_DIR="$GARUDA_DIR/bin"
LOCK_DIR="$GARUDA_DIR/lock"
LOG_DIR="$GARUDA_DIR/log"
RULES_DIR="$GARUDA_DIR/rules"

### Base path setting
FILTER_PATH="$ETC_DIR/filter.cfg"
RULE_PATH="$RULES_DIR/base.grl"
#SAMPLE_PATH="$GARUDA_DIR/802.11bdump.pcap"


### Select running mode
### 1) real-time & deamon mode
#GARUDA_OPTS="-i $DEVNAME -r $RULE_PATH -L $LOG_DIR -D -f $FILTER_PATH "
GARUDA_OPTS="-c etc/garuda.conf"

### 2) real-time & console mode
#GARUDA_OPTS="-f $FILTER_PATH -r $RULE_PATH -L $LOG_DIR -i $DEVNAME "

### 3) simulation & deamon mode
#GARUDA_OPTS="-f $FILTER_PATH -r $RULE_PATH -L $LOG_DIR -S -s $SAMPLE_PATH -D"

