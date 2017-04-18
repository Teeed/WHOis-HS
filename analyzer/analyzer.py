# -*- coding: utf-8 -*-

# Appplication that monitors users being currently in hackerspace.
# - Analyzer of whois_history table for providing some nice stats
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

import ConfigParser
import datetime
import time
import math
import os.path as path
import sqlite3
import json

'''
TODO:
 - write analysis for:
   - last data (past 4 months)
   - who is often with who

'''


class BadDataException(Exception):
	pass

class User(object):
	def __init__(self, visit_time=None, user_id=None):
		super(User, self).__init__()
		self.first_visit = 0
		self.last_visit = 0
		self.total_hourly = {}
		self.total_monthly = {}
		self.total_yearly = {}
		self.total_time = 0
		self.total_visits = 0
		self.total_weekly = {}
		self.user_id = user_id
		self.with_who = {}

		self._name = None

		if visit_time:
			self.first_visit = visit_time
			self.last_visit = visit_time

	@property
	def data(self):
		my_dict = self.__dict__.copy()
		del my_dict['user_id'] # who would EVER need to know?
		del my_dict['_name'] # who would EVER need to know?
		my_dict['total_time'] = my_dict['total_time']/(60*60)
		my_dict['average_visit_time'] = self.average_visit_time/(60*60)

		my_dict['with_who'] = {}
		for key, value in self.with_who.iteritems():
			my_dict['with_who'][key.name] = value

		return my_dict

	@property
	def name(self):
	    return self._name if self._name else self.user_id

	@name.setter
	def name(self, value):
		self._name = value
	   

	def __repr__(self): # pragma: no cover
		return str(self.name)

	@property
	def average_visit_time(self):
		if self.total_visits > 0:
			return float(self.total_time)/self.total_visits
		else:
			return 0

	def was_between(self, from_timestamp, to_timestamp=None):
		self.total_visits += 1

		if to_timestamp == None or to_timestamp == 0:
			self.update_first_last_visit(from_timestamp, from_timestamp)
			return

		if to_timestamp < from_timestamp:
			raise BadDataException('to_timestamp is lower than from_timestamp (leaved hs before entering it?)')

		timedelta = to_timestamp - from_timestamp

		self.total_time += timedelta
		how_many_hours = math.ceil((timedelta)/(60.0*60))

		self.update_first_last_visit(from_timestamp, to_timestamp)

		from_date = datetime.datetime.fromtimestamp(from_timestamp)
		to_date = datetime.datetime.fromtimestamp(to_timestamp)

		current_date = from_date

		# TODO: make it another way... this way SUCKS!
		while current_date < to_date:
			self.update_hours(current_date)
			
			self.update_weekly(current_date)
			self.update_monthly(current_date)
			self.update_yearly(current_date)

			current_date += datetime.timedelta(hours=1)

	def update_first_last_visit(self, history_from, history_to):
		if history_from < self.first_visit or self.first_visit == 0:
			self.first_visit = history_from

		if history_to > self.last_visit:
			self.last_visit = history_to

	def update_hours(self, current_timestamp):
		current_hour = current_timestamp.hour

		self._add_to_array_value('total_hourly', current_hour, 1)

	def update_weekly(self, current_timestamp):
		day_of_the_week = current_timestamp.weekday()

		self._add_to_array_value('total_weekly', day_of_the_week, 1)

	def update_monthly(self, current_timestamp):
		current_month = current_timestamp.month

		self._add_to_array_value('total_monthly', current_month, 1)

	def update_yearly(self, current_timestamp):
		current_year = current_timestamp.year

		self._add_to_array_value('total_yearly', current_year, 1)

	def update_with_who(self, friends_set):
		for friend in friends_set:
			self.with_who[friend] = self.with_who.get(friend, 0) + 1

	def _merge_array_value(self, another_user, var):
		my_var = getattr(self, var)
		for key, val in getattr(another_user, var).iteritems():
			self._add_to_array_value(var, key, val)

	def _add_to_array_value(self, name, key, number):
		getattr(self, name)[key]= getattr(self, name).get(key, 0) + number

	def __iadd__(self, another_user):
		if not isinstance(another_user, User):
			raise Exception("Trying to add something diffrent to User than User")

		self.total_time += another_user.total_time
		self.total_visits += another_user.total_visits

		self._merge_array_value(another_user, 'total_hourly')
		self._merge_array_value(another_user, 'total_weekly')
		self._merge_array_value(another_user, 'total_monthly')
		self._merge_array_value(another_user, 'total_yearly')

		self.update_first_last_visit(another_user.first_visit, another_user.last_visit)

		return self

	def __eq__(self, another):
		if (not isinstance(another, User)) or another.user_id == None or self.user_id == None:
			return False

		return self.user_id == another.user_id

class RelationAnalyzerInterval(object):
	def __init__(self, from_timestamp, to_timestamp, first_user):
		super(RelationAnalyzerInterval, self).__init__()
		self.from_timestamp = from_timestamp
		self.to_timestamp = to_timestamp
		self.users = set([ first_user ])

	def __eq__(self, another):
		return isinstance(another, RelationAnalyzerInterval) and \
			self.from_timestamp == another.from_timestamp and \
			self.to_timestamp == another.to_timestamp and \
			self.users == another.users

	def __contains__(self, another):
		return min(self.to_timestamp - another.from_timestamp, another.to_timestamp - self.from_timestamp) + 1 > 0

	def __iadd__(self, another):
		self.users.update(another.users)

		return self

	@property
	def data(self): # pragma nocover
		my_dict = self.__dict__.copy()
		return my_dict


class UserRelationAnalyzer(object):
	def __init__(self):
		super(UserRelationAnalyzer, self).__init__()
		self.intervals = set([])

	def user_was_between(self, user, from_timestamp, to_timestamp):
		if to_timestamp == 0 or to_timestamp == None:
			return
		
		need_new_interval = True
		current_interval = RelationAnalyzerInterval(from_timestamp, to_timestamp, user)
		for interval in self.intervals:
			if current_interval in interval:
				interval += current_interval # add users to this interval

				need_new_interval = False
				# break

		if need_new_interval:
			self.intervals.add(current_interval)

	def process_with_who(self):
		for interval in self.intervals:
			for user in interval.users:
				user.update_with_who(interval.users - set([user]))

class UsersAnalyzer(object):
	def __init__(self):
		super(UsersAnalyzer, self).__init__()
		self._users = {}
		self.user_relation = UserRelationAnalyzer()

	def user_was_between(self, user_id, from_timestamp, to_timestamp):
		try:
			user = self._users[user_id]
		except KeyError:
			user = User(from_timestamp, user_id)
		
			self._users[user_id] = user

		user.was_between(from_timestamp, to_timestamp)
		self.user_relation.user_was_between(user, from_timestamp, to_timestamp)

	@property
	def totals(self):
		total_user = User()
		for user_id, user in self._users.iteritems():
			total_user += user

		return total_user

	@property # pragma: no cover
	def users(self): # pragma: no cover
		return self._users

	def update_user_name(self, user_id, user_name):
		self._users[user_id].name = user_name
		self._users[user_name] = self._users[user_id]

		del self._users[user_id]

	@property
	def data(self): # pragma: no cover
		return {'users': self._users, 'total': self.totals, 'meetings': list(self.user_relation.intervals)} # pragma: no cover

if __name__ == '__main__': # pragma: no cover
	config = ConfigParser.ConfigParser()
	config.read((path.join('..', 'config.cfg'), path.join('..', 'localconfig.cfg')))

	conn = sqlite3.connect(path.join('..', config.get('database', 'db_file')))

	users_analyzer = UsersAnalyzer()

	HISTORY_ID, HISTORY_USER_ID, HISTORY_FROM, HISTORY_TO = range(4)

	for row in conn.execute('SELECT * FROM whois_history'): # 0 id, 1 user_id, 2 from, 3 to		
		users_analyzer.user_was_between(row[HISTORY_USER_ID], row[HISTORY_FROM], row[HISTORY_TO])

	users = users_analyzer.users
	for row in conn.execute('SELECT id, display_name FROM whois_users WHERE id IN (%s)' % ','.join(map(str, users.keys()))):
		users_analyzer.update_user_name(row[0], row[1])

	users_analyzer.user_relation.process_with_who()

	class MyJSONEncoder(json.JSONEncoder):
		def default(self, obj):
			if isinstance(obj, User):
				return obj.data

			if isinstance(obj, RelationAnalyzerInterval):
				dta = obj.data

				users = list()
				for user in dta['users']:
					users.append(user.name)

				dta['users'] = users

				return dta

			return super(MyJSONEncoder, self).default(obj)

	print MyJSONEncoder().encode(users_analyzer.data)
