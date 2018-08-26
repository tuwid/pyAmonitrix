#!/usr/bin/python
import timeit
from csv import writer
 
# Hit the dynamic page 100 times, time the response time
 
t = timeit.Timer("h.request('http://www.duapune.com/',headers={'cache-control':'no-cache'})","from httplib2 import Http; h=Http()")
times_p1 = t.repeat(10,1)
 
# Now hit a similar static page 100 times
#t = timeit.Timer("h.request('http://www.google.com', headers={'cache-control':'no-cache'})","from httplib2 import Http; h=Http()")
#times_p2 = t.repeat(10,1)
 
print times_p1
#print times_p2
# the times to a CSV file
#times = zip(times_p1,times_t2)
 
#with open('times.csv','w') as f:
#    w = writer(f)
#    w.writerows(times)