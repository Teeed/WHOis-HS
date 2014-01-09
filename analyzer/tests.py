# -*- coding: utf-8 -*-

# Appplication that monitors users being currently in hackerspace.
# - Analyzer of whois_history table for providing some nice stats
#   Tests to chech if everything works fine.
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

import unittest
import datetime
import time
from analyzer import *

class TestDefaultValues(unittest.TestCase):
	def runTest(self):
		user = User()
		self.assertEqual(user.first_visit, 0)
		self.assertEqual(user.last_visit, 0)

class TestDefaultValuesWhenFirstdateProvided(unittest.TestCase):
	def runTest(self):
		now = int(time.time())
		user = User(now)

		self.assertEqual(user.first_visit, now)
		self.assertEqual(user.last_visit, now)

class TestUpdatingLastSeen(unittest.TestCase):
	def setUp(self):
		self.user = User()
		self.user.was_between(100, 200)

	def test_initial(self):
		self.assertEqual(self.user.first_visit, 100)
		self.assertEqual(self.user.last_visit, 200)

	def test_updating_lastvisit_date_when_less(self):
		# test if it will update last_visit, it sould not
		self.user.was_between(100, 150)

		self.assertEqual(self.user.last_visit, 200)

	def test_updating_lastvisit_date_when_bigger(self):
		# test if it will update last_visit, it should
		self.user.was_between(100, 210)

		self.assertEqual(self.user.last_visit, 210)

	def test_updating_firstvisit_date_when_bigger(self):
		# test if it will update first_visit, it should not
		self.user.was_between(110, 200)

		self.assertEqual(self.user.first_visit, 100)

	def test_updating_firstvisit_date_when_less(self):
		# test if it will update first_visit, it should
		self.user.was_between(90, 200)

		self.assertEqual(self.user.first_visit, 90)

	def test_when_firstvisit_current(self):
		# test if it will update first_visit, it should
		self.user.was_between(90, 0)

		self.assertEqual(self.user.first_visit, 90)

	def test_when_lastvisit_current(self):
		# test if it will update first_visit, it should
		self.user.was_between(230, 0)

		self.assertEqual(self.user.last_visit, 230)

class TestUpdatingTotalVisits(unittest.TestCase):
	def setUp(self):
		self.user = User()

	def test_initial(self):
		self.assertEqual(self.user.total_visits, 0)

	def test_after_one_visit(self):
		self.user.was_between(100, 200)

		self.assertEqual(self.user.total_visits, 1)		

	def test_after_2_visits(self):
		self.user.was_between(100, 200)
		self.user.was_between(200, 300)

		self.assertEqual(self.user.total_visits, 2)	

	def test_invalid_entry(self):
		self.user.was_between(100, None)

		self.assertEqual(self.user.total_visits, 1)	

	def test_current_entry(self):
		self.user.was_between(100, 0)

		self.assertEqual(self.user.total_visits, 1)

class TestUpdatingTotalTime(unittest.TestCase):
	def setUp(self):
		self.user = User()

	def test_initial(self):
		self.assertEqual(self.user.total_time, 0)

	def test_was_between(self):
		self.user.was_between(100, 200)

		self.assertEqual(self.user.total_time, 100)

	def test_was_between_sum(self):
		self.user.was_between(100, 200)
		self.user.was_between(200, 300)

		self.assertEqual(self.user.total_time, 200)

	def test_bad_entry_do_not_increase_current_time(self):
		self.assertEqual(self.user.total_time, 0)

class TestWithDate(unittest.TestCase):
	year = 1992
	month = 1
	day = 20

	hour = 12
	minute = 36

	def _get_date(self, year, month, day, hour, minute):
		return time.mktime(datetime.datetime(year=year, month=month, day=day, hour=hour, minute=minute).timetuple())

	def _get_hour_minute(self, hour, minute):
		return self._get_date(self.year, self.month, self.day, hour, minute)

	def _get_month_day(self, month, day):
		return self._get_date(self.year, month, day, self.hour, self.minute)

class TestUpdatingTotalHoury(TestWithDate):
	def setUp(self):
		self.user = User()

	def test_initial(self):
		self.assertEqual(self.user.total_hourly, {})

	def test_some_hour(self):
		self.user.was_between(self._get_hour_minute(1, 13), self._get_hour_minute(1, 14))

		self.assertEqual(self.user.total_hourly, {1: 1})

	def test_double_in_hour(self):
		self.user.was_between(self._get_hour_minute(1, 13), self._get_hour_minute(1, 14))
		self.user.was_between(self._get_hour_minute(1, 16), self._get_hour_minute(1, 17))

		self.assertEqual(self.user.total_hourly, {1: 2})

	def test_different_hours_was_less_than_hour(self):
		self.user.was_between(self._get_hour_minute(1, 13), self._get_hour_minute(1, 14))
		self.user.was_between(self._get_hour_minute(1, 17), self._get_hour_minute(2, 2))

		self.assertEqual(self.user.total_hourly, {1: 2})

	def test_different_hours_was_longer_than_one_hour(self):
		self.user.was_between(self._get_hour_minute(1, 13), self._get_hour_minute(1, 14))
		self.user.was_between(self._get_hour_minute(1, 17), self._get_hour_minute(2, 18))

		self.assertEqual(self.user.total_hourly, {1: 2, 2: 1})

class TestUpdatingTotalHourlyDifferentDate(TestUpdatingTotalHoury):
	year = 1993
	month = 3

class TestUpdatingTotalHourlyAnotherDifferentDate(TestUpdatingTotalHoury):
	year = 2013
	month = 12

class TestUpdatingTotalMonthly(TestWithDate):
	def setUp(self):
		self.user = User()

	def test_initial(self):
		self.assertEqual(self.user.total_monthly, {})

	def test_some_month(self):
		self.user.was_between(self._get_month_day(1, 20), self._get_month_day(1, 25))

		self.assertEqual(self.user.total_monthly, {1: 24*5}) # 5 days spent

	def test_some_months(self):
		self.user.was_between(self._get_date(2013, 12, 1, 0, 0), self._get_date(2014, 1, 1, 0, 1))

		self.assertEqual(self.user.total_monthly, {1: 1, 12: 744}) 

	def test_double_in_month(self):
		self.user.was_between(self._get_month_day(1, 2), self._get_month_day(1, 3))
		self.user.was_between(self._get_month_day(1, 3), self._get_month_day(1, 5))


		self.assertEqual(self.user.total_monthly, {1: 72}) # 3 days

class TestUpdatingTotalWeekly(TestWithDate):
	def setUp(self):
		self.user = User()

	def test_initial(self):
		self.assertEqual(self.user.total_weekly, {})

	def test_some_day(self):
		self.user.was_between(self._get_date(2013, 12, 10, 12, 30), self._get_date(2013, 12, 10, 12, 31))

		self.assertEqual(self.user.total_weekly, {1: 1}) # tuesday

	def test_some_days(self):
		self.user.was_between(self._get_date(2013, 12, 10, 12, 30), self._get_date(2013, 12, 11, 12, 30))

		self.assertEqual(self.user.total_weekly, {1: 12, 2: 12}) # monday, wednesday (every 12h)

	def test_double_in_year(self):
		self.user.was_between(self._get_date(2013, 1, 20, 1, 0), self._get_date(2013, 1, 20, 19, 30))
		self.user.was_between(self._get_date(2013, 12, 10, 12, 30), self._get_date(2013, 12, 11, 12, 30))

		self.assertEqual(self.user.total_weekly, {1: 12, 2: 12, 6: 19}) 

class TestMergingUsers(TestWithDate):
	def runTest(self):
		user1 = User()
		user2 = User()

		user1.was_between(self._get_date(2013, 1, 20, 11, 00), self._get_date(2013, 1, 20, 12, 00))
		user1.was_between(self._get_date(2013, 1, 20, 13, 00), self._get_date(2013, 1, 20, 19, 00))
		user1.was_between(self._get_date(2013, 1, 21, 9, 00), self._get_date(2013, 1, 21, 19, 00))

		user2.was_between(self._get_date(2013, 1, 20, 11, 00), self._get_date(2013, 1, 20, 12, 00))
		user2.was_between(self._get_date(2013, 1, 20, 13, 00), self._get_date(2013, 1, 20, 19, 00))
		user2.was_between(self._get_date(2013, 1, 21, 9, 00), self._get_date(2013, 1, 21, 19, 00))

		user1 += user2

		self.assertEqual(user1.total_visits, 6)
		self.assertEqual(user1.total_time, user2.total_time*2)

		self.assertEqual(user1.first_visit, self._get_date(2013, 1, 20, 11, 00))
		self.assertEqual(user1.last_visit, self._get_date(2013, 1, 21, 19, 00))

		self.assertEqual(user1.total_hourly, {9: 2, 10: 2, 11: 4, 12: 2, 13: 4, 14: 4, 15: 4, 16: 4, 17: 4, 18: 4})
		self.assertEqual(user1.total_weekly, {0: 20, 6: 14})
		self.assertEqual(user1.total_monthly, {1: 34})

class TestBadMergingUsers(TestWithDate):
	def runTest(self):
		user1 = User()
		user2 = str()

		with self.assertRaises(Exception):
			user1 += user2

class TestAverageVisitTimeIfZero(unittest.TestCase):
	def runTest(self):
		user = User()

		self.assertEqual(user.average_visit_time, 0)

class TestBadTimestamps(unittest.TestCase):
	def runTest(self):
		user = User()

		with self.assertRaises(BadDataException):
			user.was_between(200, 100)

class TestUsersCompareWhenEqual(unittest.TestCase):
	def runTest(self):
		user1 = User(user_id=1)
		user2 = User(user_id=1)

		self.assertEqual(user1, user2)

class TestUsersCompareWhenDiffrent(unittest.TestCase):
	def runTest(self):
		user1 = User(user_id=1)
		user2 = User(user_id=2)

		self.assertNotEqual(user1, user2)

class TestUsersCompareWhenBadInput(unittest.TestCase):
	def runTest(self):
		self.assertFalse(User(user_id=1) == Exception())
		self.assertFalse(User(user_id=1) == User(user_id=None))
		self.assertFalse(User(user_id=None) == User(user_id=1))


class TestUserRelationalAnalyzerIntervalEq(unittest.TestCase):
	def runTest(self):
		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(100, 200, 1)

		self.assertEqual(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(100, 200, 2)

		self.assertNotEqual(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(100, 300, 1)

		self.assertNotEqual(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(90, 200, 1)

		self.assertNotEqual(int1, int2)


class TestUserRelationalAnalyzerIntervalOverlapping(unittest.TestCase):
	def assertIn(self, int1, int2):
		super(TestUserRelationalAnalyzerIntervalOverlapping, self).assertTrue(int1 in int2)
		super(TestUserRelationalAnalyzerIntervalOverlapping, self).assertTrue(int2 in int1)

	def assertNotIn(self, int1, int2):
		super(TestUserRelationalAnalyzerIntervalOverlapping, self).assertFalse(int1 in int2)
		super(TestUserRelationalAnalyzerIntervalOverlapping, self).assertFalse(int2 in int1)

	def runTest(self):
		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(100, 200, 1)

		self.assertIn(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(150, 200, 1)

		self.assertIn(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(90, 210, 1)

		self.assertIn(int1, int2)

		int1 = RelationAnalyzerInterval(100, 200, 1)
		int2 = RelationAnalyzerInterval(210, 300, 1)

		self.assertNotIn(int1, int2)

class TestRelationAnalyzerIntervalSumming(unittest.TestCase):
	def runTest(self):

		user1 = User(user_id=1)
		user2 = User(user_id=2)

		int1 = RelationAnalyzerInterval(100, 200, user1)
		int2 = RelationAnalyzerInterval(100, 200, user2)

		int1 += int2

		self.assertEqual(int1.users, set([user1, user2]))

class TestRelationAnalyzerWhenToIsIncomplete(unittest.TestCase):
	def runTest(self):
		user_relation_analyzer = UserRelationAnalyzer()
		user = User(user_id=1)

		user_relation_analyzer.user_was_between(user, 100, 0)

		self.assertEqual(user_relation_analyzer.intervals, set([]))

class TestRelationAnalyzerWhenNeedNew(unittest.TestCase):
	def runTest(self):
		user_relation_analyzer = UserRelationAnalyzer()
		user = User(user_id=1)
		interval = RelationAnalyzerInterval(100, 200, user)

		user_relation_analyzer.user_was_between(user, 100, 200)

		self.assertEqual(len(user_relation_analyzer.intervals), 1)
		self.assertEqual(user_relation_analyzer.intervals.pop(), interval)

class TestRelationAnalyzerMerge(unittest.TestCase):
	def runTest(self):
		user_relation_analyzer = UserRelationAnalyzer()
		user1 = User(user_id=1)
		user2 = User(user_id=2)

		user_relation_analyzer.user_was_between(user1, 100, 200)
		user_relation_analyzer.user_was_between(user2, 150, 200)

		self.assertEqual(len(user_relation_analyzer.intervals), 1)
		self.assertEqual(user_relation_analyzer.intervals.pop().users, set([user1, user2]))

class TestUsersAnalyzerUpdating(unittest.TestCase):
	def runTest(self):
		users_analyzer = UsersAnalyzer()

		users_analyzer.user_was_between(1, 100, 200)

		self.assertEqual(users_analyzer._users, {1: User(user_id=1)})

		users_analyzer.user_was_between(1, 200, 300)		

		self.assertEqual(users_analyzer._users, {1: User(user_id=1)})

		total = users_analyzer.totals

		self.assertEqual(total.total_time, 200)

		users_analyzer.update_user_name(1, 'Test Name')

		self.assertEqual(users_analyzer._users['Test Name'].name, 'Test Name')

class TestEndData(TestWithDate):
	def setUp(self):
		self.user = User()

		self.user.was_between(self._get_date(2013, 1, 20, 11, 00), self._get_date(2013, 1, 20, 12, 00))
		self.user.was_between(self._get_date(2013, 1, 20, 13, 00), self._get_date(2013, 1, 20, 19, 00))
		self.user.was_between(self._get_date(2013, 1, 21, 9, 00), self._get_date(2013, 1, 21, 19, 00))

	def test_average_visit_time(self):
		self.assertEqual(self.user.average_visit_time, 20400.0)

	def test_final_data(self):
		user_data = self.user.data

		self.assertEqual(set(user_data.keys()), set(['total_time', 'first_visit', 'average_visit_time', 'last_visit', 'total_weekly', 'total_monthly', 'total_hourly', 'total_visits', 'with_who']))

if __name__ == '__main__':
    unittest.main()