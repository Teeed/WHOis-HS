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

import zmq
from random import randrange

context = zmq.Context()

socket_in = context.socket(zmq.DEALER)
socket_in.bind("ipc://zmq-whois-pubsub-server")

socket_out = context.socket(zmq.PUB)
socket_out.bind("tcp://*:5556")

zmq.proxy(socket_in, socket_out)

socket.close()
context.term()
