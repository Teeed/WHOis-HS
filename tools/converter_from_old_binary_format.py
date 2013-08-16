import web
import binascii

def mac_to_binary(mac):
	return binascii.unhexlify(mac.replace(':', ''))

def binary_to_mac(binary):
	s = binascii.hexlify(binary)
	return ':'.join( (s[i:i+2] for i in range(0, len(s), 2)) )

db_old = web.database(dbn='sqlite', db='database_old.db')
db = web.database(dbn='sqlite', db='database_new.db')

for r in db_old.query('SELECT * FROM whois_users'):
	db.insert('whois_users', id=r['id'], display_name=r['display_name'], login=r['login'], 
		password=binascii.hexlify(r['password']), access_key=r['access_key'], registered_at=r['registered_at'],
		last_login=r['last_login'])

for r in db_old.query('SELECT * FROM whois_devices'):
	db.insert('whois_devices', mac_addr=binary_to_mac(r['mac_addr']), user_id=r['user_id'], last_seen=r['last_seen'])

for r in db_old.query('SELECT * FROM whois_history'):
	db.insert('whois_history', id=r['id'], user_id=r['id'], date_from=r['date_from'], date_to=r['date_to'])