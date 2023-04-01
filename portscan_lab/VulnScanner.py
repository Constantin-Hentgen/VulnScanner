#!/usr/bin/python

import socket, optparse, threading, sys, os

class colors:
	OPEN = '\033[92m'
	CLOSED = '\033[91m'
	VERSION = '\033[94m'
	VULNERABLE = '\033[93m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	HEADER = '\033[95m'

def portScan(host, port, service, quiet, vuln_services):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(10)
		sock.connect((host,port))

		if not service:
			print(colors.OPEN + f"port {port} open")

		else:
			banner_text = ""
			vuln_text = ""
			try:
				banner = retBanner(sock, port)
				banner_text = f"{colors.ENDC} {banner}" if banner else ""
				try:
					vuln_text = f"{colors.VULNERABLE}{colors.UNDERLINE}vulnerable{colors.ENDC}" if is_vulnerable(banner, vuln_services) else ""
				except TypeError:
					pass
			except OSError:
				pass
			finally:
				print(f"{colors.BOLD}{colors.HEADER}{colors.OPEN}  port {str(port).ljust(4)} open {banner_text} {colors.ENDC} {vuln_text}")
	except socket.error:
		if not quiet:
			print(f"{colors.CLOSED} port {port} closed or filtered")
	finally:
		sock.close()

def get_vuln_banners(filepath):
	try:
		with open(options.filename) as f:
			return f.read()
	except FileNotFoundError:
		print(f"File not found: {options.filename}")

def is_vulnerable(service, vuln_services):
	with open(vuln_services, 'r') as file:
		source = file.read()
	vulns = []

	for line in source.splitlines():
		vulns.append(line.strip())

	for vuln in vulns:
		if vuln in service:
			return True
	return False

def retBanner(sock, port):
	if port in [80,443]:
		sock.send(b'GET /\n\n')
		banner = get_server_name(sock.recv(1024).decode())
	else:
		try:
			banner = sock.recv(1024).decode()
		except UnicodeDecodeError:
			banner = sock.recv(1024)

	return banner.split("\n")[0]

def get_server_name(response):
	server_name = ""
	for line in response.split("\n"):
		if line.startswith("Server:"):
			server_name = line.split(": ")[1]
			break
	if server_name:
		server_name = f"| server : {server_name}"
	
	return server_name

def main():
	parser = optparse.OptionParser()
	parser.add_option("-H", "--host", help="give host ip or domain")
	parser.add_option("-p", "--ports", help="specify the ports number")
	parser.add_option("-s", "--service", help="get banner", action="store_true")
	parser.add_option("-a", "--allports", help="scan all first 1024 ports", action="store_true")
	parser.add_option("-q", "--quiet", help="display only open ports", action="store_true")
	parser.add_option("-f", "--file", help="input vulnerable services banner", metavar="FILE")

	(options, args) = parser.parse_args()

	socket.setdefaulttimeout(1)

	try:
		host = socket.gethostbyname(options.host)
	except socket.gaierror:
		print('Name resolution failed')
		exit(1)

	service = options.service
	quiet = options.quiet
	vuln_services = options.file

	all_ports = options.allports

	if all_ports:
		ports = [i for i in range(1,1025)]
	else:
		ports = [int(p) for p in options.ports.split(",")]

	if options.host and (options.ports or options.allports):
		print(''' __     __          _           ____                                               
 \ \   / /  _   _  | |  _ __   / ___|    ___    __ _   _ __    _ __     ___   _ __ 
  \ \ / /  | | | | | | | '_ \  \___ \   / __|  / _` | | '_ \  | '_ \   / _ \ | '__|
   \ V /   | |_| | | | | | | |  ___) | | (__  | (_| | | | | | | | | | |  __/ | |   
    \_/     \__,_| |_| |_| |_| |____/   \___|  \__,_| |_| |_| |_| |_|  \___| |_|   
	''')
		for port in ports:
			t = threading.Thread(target=portScan, args=(host,port,service,quiet,vuln_services,))
			t.start()
	else:
		exit(0)

if __name__ == "__main__":
	main()