import calendar
import datetime

yob = 1980
ytoday = datetime.datetime.now().year + 10

for y in range(ytoday - yob + 1):
    currenty = y + yob
    currentday = datetime.datetime(currenty, 4, 5)
    print('%s: %s' % (currenty, calendar.day_name[currentday.weekday()]))
