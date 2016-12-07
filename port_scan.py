#!/usr/bin/python
#coding:utf-8
#filename : port_scan.py
#auth : 0wen
# 2016/12/6
from scapy.all import *
import logging
import argparse
from prettytable import PrettyTable
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def tcp_connect_scan(dstip,dstport, dst_timeout):
	print dst_timeout
	srcport = RandShort()
	#握手第一步：
	try:
		tcp_connect_scan_response = sr1(IP(dst=dstip)/TCP(sport=srcport, dport=dstport,flags="S"), timeout=dst_timeout)  
		if str(type(tcp_connect_scan_response)) == "<class 'NoneType'>":
			#tcp_connect_scan(dstip, dstport, dst_timeout)
			return "Closed"
		#print tcp_connect_scan_response.getlayer(TCP).flags
		elif tcp_connect_scan_response.getlayer(TCP):
			#print "ok"
			if int(tcp_connect_scan_response.getlayer(TCP).flags) == 18:
				send_request = sr(IP(dst=dstip)/TCP(sport=srcport, dport=dstport,flags="AR"),timeout=dst_timeout)
				return "Open"
			elif int(tcp_connect_scan_response.getlayer(TCP).flags) == 20:
				return "Closed"
		else:
			print "ok"
	except AttributeError, e:
		e
#print tcp_connect_scan()


def start_scan(target,ports,timeout):
	x = PrettyTable(["Port NO.","tcp_connect"])
	x.align['Port No.'] = '1'
	print "[*]start\n"
	for port in ports:
		tcp_connect_scan_result = tcp_connect_scan(target,int(port),timeout)
		x.add_row([port,tcp_connect_scan_result])
	print x
def banner():
	banner = "this is a port_scan"
def main():
	parser = argparse.ArgumentParser(description=banner())
	parser.add_argument("target", help="目的地址")
	parser.add_argument("-pl","--portlist", help="指定一个或多个端口,如：80,3306")
	parser.add_argument("-pr","--portrange",help="端口扫描范围,如 20-80(不包括80)")
	parser.add_argument("-t","--time",type=int, default=1, help="超时时间，默认为1")
	args = parser.parse_args()
	port = []
	target = args.target
	if args.portlist:
		ports = list((args.portlist).split(","))   #pl为列表
		#return pl
	if args.portrange:
		pr = list((args.portrange).split("-"))
		ports = range(int(pr[0]),int(pr[1]))
		#return pr_list
	timeout = int(args.time)
	start_scan(target,ports,timeout)


if __name__ == "__main__":
	main()
