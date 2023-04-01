#!/usr/bin/python

import socket, optparse, threading

class colors:
	OPEN = '\033[92m'
	CLOSED = '\033[91m'

def portScan(host, port, service, quiet):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(5)
		sock.connect((host,port))

		if not service:
			print(colors.OPEN + 'port {} open'.format(port))

		else:
			try:
				banner = retBanner(sock, port)
				banner_text = f" | {banner}" if banner else ""
				print(colors.OPEN + f"port {port} open {banner_text}")

			except OSError:
				pass
	except socket.error:
		if not quiet:
			print(colors.CLOSED + 'port {} closed or filtered'.format(port))
	finally:
		sock.close()

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

	(options, args) = parser.parse_args()

	socket.setdefaulttimeout(1)

	try:
		host = socket.gethostbyname(options.host)
	except socket.gaierror:
		print('Name resolution failed')
		exit(1)

	service = options.service
	quiet = options.quiet

	all_ports = options.allports

	if all_ports:
		ports = [i for i in range(1,1025)]
	else:
		ports = [int(p) for p in options.ports.split(",")]

	if options.host and (options.ports or options.allports):
		for port in ports:
			t = threading.Thread(target=portScan, args=(host,port,service,quiet,))
			t.start()
	else:
		exit(0)

if __name__ == "__main__":
	main()