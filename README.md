
What is the garuda ?
======================================================================

 garuda is a wireless intrusion detection system (WIDS) , supports 
 802.11 wireless lan. it's designed for detecting  war drivers, 
 rouge ap, DoS attacks and even MAC spoofing,  including rule-based 
 detection module, statistics module, enummeration module.

 it has following special features 
  * Detection War-Driving devices using Netstumber or Pocket Warrior
  * Detection Null probing
  * Detection Denial of Service Attack
  * Detection MAC Spoofing users
  * Detection various wireless attacks felxibly by adding/modifying rule-based 
    detection entry 
  * Detection attacks on layer 2, layer 3, layer 4 and  upper layer 

 it has also following useful features
  * Enumeration of wireless AP and mobile station
  * Enumeration of current session 
  * Statistics for local wireless network
  * Handling rule-based detecting module

 first released at http://garuda.sourceforge.net , 2004 
 not maintenanced now, only for academic purpose 
	

Quick Installation 
======================================================================
```
$ git clone git@github.com:truefinder/garuda.git
$ cd garuda 
$ make 
$ make install
```


Start & Stop 
======================================================================

* Start 
``` 
 # ./rungaruda start
```
* Stop
``` 
 # ./rungaruda stop
```
* Clear
If you failed to start or stop, clear garbage files 
```
# ./rungaruda clear 
```


Description of each directories 
======================================================================

```
 src/  ==> source codes 
 etc/  ==> configuration files 
 scripts/ ==> install, configuration, aironet-rfmon triggers ... etc
 rules/ ==> detection rules
 doc/ ==> documents about garuda 
 templets/ ==> recommaned source code templetes
```


Recommanded packages 
======================================================================

* linux kernel 2.4.26 or higher
* pcmacia-cs-3.2.7 or higher
* airo-linux current CVS version or Cisco provided driver
* openssl-0.9.7a-2 or higher
* libpacp-0.7.2-1 or higher

Any linux is also good selection to run garuda



Contacts 
======================================================================

Seunghyun Seo 



