#!/usr/bin/python
#coding:utf-8
#filename : arp_scan.py
#auth : 0wen
# 2016/12/6
import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) !=2:
	print "[*]Usage:         python arp_scan.py [interface]"
	print "[*]Example:       python arp_scan.py en0"
	sys.exit()
interface = str(sys.argv[1])

ip = subprocess.check_output("ifconfig "+interface+ " | grep 'inet '|cut -d '.' -f 1-3|cut -d ' ' -f 2",shell=True).strip()
#print ip
for add in range(1,254):
	try:
		answer = sr1(ARP(pdst=ip+'.'+str(add)),timeout=1, verbose=0)
	except AttributeError, e:
		e
	if answer == None:
		pass
	else:
		print ip+"."+str(add)
