-- MySQL dump 8.22
--
-- Host: localhost    Database: garuda
---------------------------------------------------------
-- Server version	3.23.54

--
-- Table structure for table 'detect'
--

CREATE TABLE detect (
  did int(11) NOT NULL auto_increment,
  first_seen datetime default '0000-00-00 00:00:00',
  hostname varchar(32) default NULL,
  rule_id int(11) default '0',
  type int(11) default '0',
  risk int(11) default '0',
  src_maddr varchar(32) default NULL,
  dst_maddr varchar(32) default NULL,
  bssid_maddr varchar(32) default NULL,
  ssid varchar(64) default NULL,
  desc tinytext,
  PRIMARY KEY  (did)
) TYPE=MyISAM;

--
-- Dumping data for table 'detect'
--



--
-- Table structure for table 'member'
--

CREATE TABLE member (
  mid int(11) NOT NULL auto_increment,
  first_seen datetime NOT NULL default '0000-00-00 00:00:00',
  seq int(11) NOT NULL default '0',
  obj_type int(11) NOT NULL default '0',
  src_maddr varchar(32) default NULL,
  bssid_maddr varchar(32) default NULL,
  src_ip varchar(32) default NULL,
  ssid varchar(64) default NULL,
  channel int(11) default NULL,
  PRIMARY KEY  (mid)
) TYPE=MyISAM;

--
-- Dumping data for table 'member'
--



--
-- Table structure for table 'session'
--

CREATE TABLE session (
  sid int(11) NOT NULL auto_increment,
  first_seen datetime NOT NULL default '0000-00-00 00:00:00',
  last_seen datetime NOT NULL default '0000-00-00 00:00:00',
  pkt_count int(11) default '0',
  tot_size int(11) default NULL,
  src_maddr varchar(32) default NULL,
  dst_maddr varchar(32) default NULL,
  bssid_maddr varchar(32) default NULL,
  src_ip varchar(32) default NULL,
  src_port int(11) default NULL,
  dst_ip varchar(32) default NULL,
  dst_port int(11) default NULL,
  PRIMARY KEY  (sid)
) TYPE=MyISAM;

--
-- Dumping data for table 'session'
--



--
-- Table structure for table 'statistics'
--

CREATE TABLE statistics (
  sid int(11) NOT NULL auto_increment,
  datetime datetime default NULL,
  mgt_assoc_req int(11) default NULL,
  mgt_assoc_resp int(11) default NULL,
  mgt_reassoc_req int(11) default NULL,
  mgt_reassoc_resp int(11) default NULL,
  mgt_probe_req int(11) default NULL,
  mgt_probe_resp int(11) default NULL,
  mgt_beacon int(11) default NULL,
  mgt_atim int(11) default NULL,
  mgt_disass int(11) default NULL,
  mgt_authentication int(11) default NULL,
  mgt_deauthentication int(11) default NULL,
  ctrl_ps_poll int(11) default NULL,
  ctrl_rts int(11) default NULL,
  ctrl_cts int(11) default NULL,
  ctrl_acknowledgement int(11) default NULL,
  ctrl_cfp_end int(11) default NULL,
  ctrl_cfp_endack int(11) default NULL,
  data int(11) default NULL,
  data_cf_ack int(11) default NULL,
  data_cf_poll int(11) default NULL,
  data_cf_ack_poll int(11) default NULL,
  data_null_function int(11) default NULL,
  data_cf_ack_nod int(11) default NULL,
  data_cf_poll_nod int(11) default NULL,
  data_cf_ack_poll_nod int(11) default NULL,
  PRIMARY KEY  (sid)
) TYPE=MyISAM;

--
-- Dumping data for table 'statistics'
--



--
-- Table structure for table 'trial'
--

CREATE TABLE trial (
  tid int(11) NOT NULL auto_increment,
  first_seen datetime default NULL,
  src_maddr varchar(32) default NULL,
  pkt_type varchar(32) default NULL,
  ssid int(64) default NULL,
  PRIMARY KEY  (tid)
) TYPE=MyISAM;

--
-- Dumping data for table 'trial'
--



