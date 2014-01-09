# -*- coding: utf-8 -*-

# Appplication that monitors users being currently in hackerspace.
# - Pub-sub server for HS-WhoIs
#
# Copyright (C) 2013 Tadeusz Magura-Witkowski
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


ZMQ_MESSAGE_USER_INITIAL, ZMQ_MESSAGE_USER_IN, ZMQ_MESSAGE_USER_OUT = range(3)

def main():
	import zmq
	import json
	from random import randrange

	import ConfigParser

	config = ConfigParser.ConfigParser()
	config.read(('config.cfg', 'localconfig.cfg'))

	context = zmq.Context()

	socket_in = context.socket(zmq.SUB)
	socket_in.setsockopt(zmq.SUBSCRIBE, '%3d' % (ZMQ_MESSAGE_USER_INITIAL))
	socket_in.bind(config.get('zmq_server', 'zmq_server_addr')) # receive ZMQ_MESSAGE_USER_INITIAL from webapp

	socket_out = context.socket(zmq.XPUB)
	socket_out.bind(config.get('zmq_server', 'zmq_pubsub_addr'))

	last_users = {}

	poller = zmq.Poller()
	poller.register(socket_in, zmq.POLLIN)
	poller.register(socket_out, zmq.POLLIN)

	while True:
		events = dict(poller.poll())

		if socket_in in events:
			msg = socket_in.recv()
			users = json.loads(msg[3:])
			users_ids_now = set(users.keys())
			last_users_ids = set(last_users.keys())

			users_in = users_ids_now - last_users_ids
			if len(users_in):
				new_users = dict((key, value) for (key, value) in users.iteritems() if key in users_in)
				# new_users = {key:value for (key, value) in users.iteritems() if key in users_in}
				socket_out.send("%3d%s" % (ZMQ_MESSAGE_USER_IN, json.dumps( new_users )))

			users_out = last_users_ids - users_ids_now
			if len(users_out):
				users_left = dict((key, value) for (key, value) in last_users.iteritems() if key in users_out)
				# users_left = {key:value for (key, value) in last_users.iteritems() if key in users_out}
				socket_out.send("%3d%s" % (ZMQ_MESSAGE_USER_OUT, json.dumps( users_left )))

			last_users = users


		if socket_out in events:
			event = socket_out.recv()

			if event[0] == b'\x01': # sub
				socket_out.send("%3d%s" % (ZMQ_MESSAGE_USER_INITIAL, json.dumps( last_users )))


	socket.close()
	context.term()


if __name__ == '__main__':
	main()

