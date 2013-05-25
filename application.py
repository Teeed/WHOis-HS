# -*- coding: utf-8 -*-
from web import form
import web
import json
import binascii
import sqlite3
import time
import hashlib
import string
import random
import datetime
import netsnmp
import ConfigParser

config = ConfigParser.ConfigParser()
config.read(('config.cfg', 'localconfig.cfg'))

web.config.debug = config.getboolean('application', 'debug')

def mac_to_binary(mac):
	return binascii.unhexlify(mac.replace(':', ''))

def binary_to_mac(binary):
	s = binascii.hexlify(binary)
	return ':'.join( (s[i:i+2] for i in range(0, len(s), 2)) )

def convert_date_to_fucking_human_readable_format_the_hell_cause_unix_timestamp_is_fucking_bad_for_peoples_eyes(timestamp):
	return datetime.datetime.fromtimestamp(timestamp).strftime('%d/%m/%Y %H:%M')

db = web.database(dbn='sqlite', db=config.get('database', 'db_file'))
render = web.template.render('templates', base='base', globals={'binary_to_mac': binary_to_mac,
	'BASE_URL': config.get('application', 'base_url'),
	'date': convert_date_to_fucking_human_readable_format_the_hell_cause_unix_timestamp_is_fucking_bad_for_peoples_eyes,})

urls = (
	'/', 'index',
	'/whois', 'who_is',
	r'^/r/(\d+)/(.{10})$', 'register_device',
	'/register', 'register_user',
	'/panel', 'user_panel',
	'/logout', 'user_logout',
	'/panel/editprofile', 'user_edit_profile',
	r'/panel/removedevice/(.{17})', 'user_remove_device',
)

app = web.application(urls, globals())

if web.config.get('_session') is None:
	session = web.session.Session(app, web.session.DiskStore('sessions'), {'user_id': 0})
	web.config._session = session
else:
	session = web.config._session

def hash_password(username, password):
	hash = '%s%s%s' % (username, password, config.get('application', 'hash_secret'))
	for i in range(20):
		hash = hashlib.sha256(hash).digest()

	return hash

def generate_access_key():
	return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(10))

def get_current_users():
	# for testing only
	# time.sleep(2)
	# return [('127.0.0.1', mac_to_binary('AA:BB:CC:DD:EE:FF')), ('192.168.1.7', mac_to_binary('AA:BB:CC:DD:EE:F0')), ]

	# final version will use this.. but.. this should work but it does not :(
	# we will investigate it later
	#varlist = netsnmp.VarList(netsnmp.Varbind(config.get('snmp', 'tree')))
	#response = netsnmp.snmpwalk(varlist, DestHost=config.get('snmp', 'query_host'), Version=config.getint('snmp', 'version'), Community=config.get('snmp', 'community'), Timeout=config.getint('snmp', 'timeout'))

	#users = []
	#i = 0

	#for var in varlist:
	#	users.append( (varlist[i].iid[config.getint('snmp', 'sub'):], response[i]) )
	#	i += 1


	# very, very dirty one! JUST FOR NOW :(
	import subprocess, re
	subp = subprocess.Popen(('snmpwalk', '-v', config.get('snmp', 'version'), '-c', config.get('snmp', 'community'), config.get('snmp', 'query_host'), 'IP-MIB::%s' % config.get('snmp', 'tree')), stdout=subprocess.PIPE)
	out, err = subp.communicate()

	rgx = re.compile(r'^(.*) = STRING: (.*)$')
	users = []

	for entry in out.split('\n'):
		mtch = rgx.match(entry[config.getint('snmp', 'sub'):])

		if not mtch:
			continue

		mac = []

		for z in mtch.group(2).split(':'):
			if len(z) < 2:
				z = '0%s' % z

			mac.append(z)

		mac = ':'.join(mac)

		print mtch.group(1), mac

		mac = mac_to_binary(mac)

		users.append((mtch.group(1), mac))

	return users

class who_is:
	last_seen_updated = 0
	last_seen_list = []
	total_devices_count = 0

	def GET(self):
		web.header('Content-type', 'application/json')

		# TODO: think if it makes any sense to use interval instead of this method..
		if who_is.last_seen_updated < time.time():
			dhcp_leases = get_current_users()
			query_for = [sqlite3.Binary(lease[1]) for lease in dhcp_leases]
			
			# no idea why DISTINCT does not work.. we will use set instead of list to prevent duplicates
			# we will also display number of unregistered devices
			# TODO: Fix this!
			users = set([])

			if len(dhcp_leases):
				db.query('UPDATE whois_devices SET last_seen = strftime(\'%s\',\'now\') WHERE mac_addr IN $mac_list', vars=
					{'mac_list': query_for})

				results = db.query('SELECT DISTINCT display_name FROM whois_users WHERE id IN (SELECT user_id FROM whois_devices WHERE mac_addr IN $macs)', vars=
					{'macs': query_for})

				for user in results:
					users.add(user['display_name'])

			who_is.last_seen_updated = int(time.time()) + 60*10
			who_is.total_devices_count = len(query_for)
			who_is.last_seen_list = list(users)

		return json.dumps({'date': who_is.last_seen_updated, 'users': who_is.last_seen_list, 'total_devices_count': who_is.total_devices_count})
        
class register_device:
	def GET(self, uid, access_key):
		uid = int(uid)

		result = db.query('SELECT * FROM whois_users WHERE id == $uid AND access_key == $access_key', vars={'uid': uid, 'access_key': access_key})
		
		if not result:
			raise web.badrequest(u'Zły uid lub access_key. Sprawdź czy wszedłeś pod poprawy adres URL. Jeżeli tak, to pamiętaj, że przy każdym logowaniu Twój adres jest generowany na nowo. Spróbuj zatem zalogować się ponownie i użyć nowego adresu.')

		user_ip = web.ctx.env.get('REMOTE_ADDR')
		user_mac = None
		dhcp_leases = get_current_users()

		for lease in dhcp_leases:
			if lease[0] == user_ip:
				user_mac = lease[1]

				break

		if not user_mac:
			raise web.badrequest(u'Czy jesteś pewien, że korzystasz z HS-owego WIFI? Jeżeli tak, to powiadom kogoś o tym błędzie!')

		result = db.query('SELECT * FROM whois_devices WHERE mac_addr == $mac_addr', vars={'mac_addr': sqlite3.Binary(user_mac)})

		if result:
			raise web.badrequest(u'Twoje urządzenie jest już zarejestrowane!')

		db.insert('whois_devices', mac_addr=sqlite3.Binary(user_mac), user_id=uid, last_seen=int(time.time()))

		return u'Brawo! Właśnie dokonałeś rejestracji swojego urządzenia w systemie :) Od tej chwili jego obecność będzie oznaczało również Twoją.'

password_validator = form.regexp(r'.{3,100}$', u'od 3 do 100 znaków')
display_name_validator = form.regexp(r'.{3,100}$', u'od 3 do 100 znaków')
unique_username_validator = form.Validator(u'Podana nazwa użytkownika jest już zajęta', lambda f: 
						db.query('SELECT COUNT(id) AS cnt FROM whois_users WHERE login == $login', vars={'login': f.login})[0]['cnt'] == 0)
password_match_validator = form.Validator(u'Hasła w dwóch polach się nie zgadzają', lambda i: i.password == i.password2)
unique_display_name_validator = form.Validator(u'Ktoś już używa takiej nazwy...', lambda f: 
						db.query('SELECT COUNT(id) AS cnt FROM whois_users WHERE display_name == $display_name', vars={'display_name': f.display_name})[0]['cnt'] == 0)
login_validator = form.regexp(r'[a-zA-Z0-9_]{3,32}$', u'od 3 do 32 znaków, alfanumeryczny')

class register_user:
	register_form = form.Form(
		form.Textbox('login', login_validator, description='Login'),
		form.Textbox('display_name', display_name_validator, description=u'Nazwa wyświetlana'),
		form.Password('password', password_validator, description=u'Hasło'),
		form.Password('password2', description=u'Powtórz hasło'),
		form.Button('submit', type='submit', html='Zarejestruj'),
		validators = [password_match_validator, unique_username_validator, unique_display_name_validator])

	def GET(self):
		f = register_user.register_form()

		return render.register(f)

	def POST(self):
		f = register_user.register_form()

		if not f.validates():
			f.password.value = f.password2.value = ''
			return render.register(f)
		else:
			data = f.d
			del data['password2']
			del data['submit']
			data['password'] = sqlite3.Binary(hash_password(data['login'], data['password']))
			data['registered_at'] = int(time.time())
			data['access_key'] = generate_access_key()

			session.user_id = db.insert('whois_users', **data)

			raise web.seeother('/panel')

def get_userrow():
	return db.query('SELECT * FROM whois_users WHERE id = $id', vars={'id': session.user_id})[0]

class user_edit_profile:
	edit_form = web.form.Form(
		form.Textbox('display_name', description=u'Nazwa wyświetlana'),
		form.Password('password', description=u'Nowe hasło'),
		form.Password('password2', description=u'Powtórzenie nowego'),
		form.Password('old_password', description=u'Stare hasło'),
		form.Button('submit', type='submit', html=u'Zmień'),
		validators=[]
	)

	def GET(self):
		if not session.user_id:
			raise web.seeother('/panel')

		try:
			userrow = get_userrow()
		except:
			session.kill()

			raise web.seeother('/panel')

		f = user_edit_profile.edit_form()
		
		return render.editprofile(f)

	def POST(self):
		if not session.user_id:
			raise web.seeother('/panel')

		f = user_edit_profile.edit_form()

		if not f.validates():
			return render.editprofile(f)

		if f.d['password']:

			userrow = get_userrow()

			def check_old_password(i):
				return hash_password(userrow['login'], i) == bytes(userrow['password'])

			check_password_validator = form.Validator('is invalid', check_old_password)

			f.validators.append( password_match_validator )
			f.password.validators = [password_validator]
			f.old_password.validators = [password_validator, check_password_validator]

		if f.d['display_name']:
			f.validators.append( unique_display_name_validator )
			f.display_name.validators = [display_name_validator]

		if not f.validates():
			return render.editprofile(f)

		data_to_change = {'where': 'id = $id', 'vars': {'id': session.user_id}}

		if f.d['password']: # changing password
			data_to_change['password'] = sqlite3.Binary(hash_password(userrow['login'], f.d.password))

		if f.d['display_name']: # changing display name
			data_to_change['display_name'] = f.d['display_name']

		if len(data_to_change.keys()) > 2: # if changing anything
			db.update('whois_users', **data_to_change)

		raise web.seeother('/panel')

class user_panel:
	login_form = form.Form(
		form.Textbox('login', login_validator, description='Login'),
		form.Password('password', password_validator,description=u'Hasło'),
		form.Button('submit', type='submit', html=u'Zaloguj się'))

	def GET(self):
		if not session.user_id:
			return render.login(user_panel.login_form())

		try:
			userrow = get_userrow()
			devices = db.query('SELECT * FROM whois_devices WHERE user_id = $user_id', vars={'user_id': userrow['id']})
		except:
			session.kill()

			raise web.seeother('/panel')

		return render.panel(userrow, devices)

	def POST(self):
		if session.user_id:
			raise web.seeother('/panel')

		f = user_panel.login_form()

		if not f.validates():
			f.password.value = ''
			return render.login(f)

		result = db.query('SELECT id FROM whois_users WHERE login == $login AND password == $password', 
			vars={'login': f.d.login, 'password': sqlite3.Binary(hash_password(f.d.login, f.d.password))})

		try:
			uid = result[0]['id']
		except:
			time.sleep(5) # to slow down brute-force attemps
			f.password.value = ''
			return render.login(f, True)

		db.query('UPDATE whois_users SET last_login = strftime(\'%s\',\'now\'), access_key = $access_key WHERE id = $id', vars=
			{'access_key': generate_access_key(), 'id': uid})
	
		session.user_id = uid

		raise web.seeother('/panel')

class user_remove_device:
	def GET(self, device_mac):
		if not session.user_id:
			raise web.seeother('/panel')

		try:
			mac_addr = sqlite3.Binary(mac_to_binary(device_mac))

			devicerow = db.query('SELECT * FROM whois_devices WHERE mac_addr = $mac_addr', vars=
				{'mac_addr': mac_addr})[0]


			if devicerow.user_id != session.user_id:
				raise web.badrequest(u'To urządzenie nie jest Twoje!')

			db.delete('whois_devices', where='mac_addr = $mac_addr', vars=
				{'mac_addr': mac_addr})
		except web.badrequest as e:
			raise e
		except:
			pass

		raise web.seeother('/panel')

class index:
	def GET(self):
		return render.index()

class user_logout:
	def GET(self):
		session.kill()

		raise web.seeother('/panel')

if __name__ == '__main__':
	db.query('CREATE TABLE IF NOT EXISTS whois_users (id INTEGER PRIMARY KEY AUTOINCREMENT, display_name VARCHAR(100), login VARCHAR(32) UNIQUE, password BLOB(32), access_key VARCHAR(10), registered_at INTEGER, last_login INTEGER)')
	db.query('CREATE TABLE IF NOT EXISTS whois_devices (mac_addr BLOB(6) PRIMARY KEY UNIQUE, user_id INTEGER, last_seen INTEGER)')

	app.run()
