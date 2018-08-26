import dns.resolver
import string

my_resolver = dns.resolver.Resolver()
my_resolver.nameservers = ['8.8.4.4'] #set name servers seperated by comma
stuff = my_resolver.query("googlaaaaae.com","A")

# duhet pa rasti per nx domain
for h in stuff:
	print h

