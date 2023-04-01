#!/usr/bin/python

import socket

class colors:
	OPEN = '\033[92m'
	CLOSED = '\033[91m'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 443

print(host, port)

def portscanner(host, ports):
	for port in ports:
		if (sock.connect_ex((host, port)) == 0):
			print(colors.OPEN + 'port {} open'.format(port))
		else:
			print(colors.CLOSED + 'port {} closed or filtered'.format(port))

def scan_first_1000_ports():
	portscanner("127.0.0.1",[i for i in range(1,1025)])


# portscanner(port)
# scan_first_1000_ports()