from bs4 import BeautifulSoup

import requests

#url = "pbx.webservice01.com"

r  = requests.get("http://pbx.webservice01.com/")

data = r.text

soup = BeautifulSoup(data)

for tag in soup.find_all(True):
    if tag.name == "script":
		test = tag.attrs
		if test:
			print test['src']
		#	print str(tag.attrs)
		#if tag.attrs['src'] != None:
		#	print tag.attrs['src']
    #if tag.name == "img":
	#		print tag.attrs['src']
    if tag.name == "link":
		print tag.attrs['href']
    #print(tag.name) + str(tag.attrs)

#<script src=
#<link rel="
#<input type="image" src=
