from web import form
import web
import sqlite3
import sys
import hashlib
from application import hash_password


db = web.database(dbn='sqlite', db='database.db')


db.query('UPDATE whois_users SET password = $password WHERE login = $login', vars=
	{'login': sys.argv[1], 'password': hash_password(sys.argv[1], sys.argv[1])})

