#! /usr/bin/env python

from collections import Counter
import subbrute
from time import sleep
# This could be cleaner
import requests
from requests.exceptions import ConnectionError
from requests import get

#! Get all subdomains
subdomains = subbrute.run("gov.in")

# Eliminate duplicates from multiple dns record types
subdomain_names = list(set((i[0] for i in subdomains)))
subdomain_names.sort()

# Get a list of all subdomains that respond to http requests
webs = []
for d in subdomain_names:
    #B3Cool
    sleep(0.1)
    try:
        get('http://{}/'.format(d))
        webs.append(d)
    except ConnectionError:
        # We tried making http requests to something that wasn't
        # listening on port 80
        pass

# Get a list of all subdomains that respond to https requests
secure_webs = []
insecure_webs = {}
for w in webs:
    #B3CoolStill
    sleep(0.1)
    try:
        get('https://{}/'.format(w), verify=True)
        # Collect valid webs
        secure_webs.append(w)
    except Exception as e:
        # Collect invalid webs, including errors
        insecure_webs[w] = e

# We're done now
# Let's do some stats

# Filter out webs that aren't available over https
webs_without_ssl = []
webs_with_bad_ssl = {}

for k, v in insecure_webs.iteritems():
    # Since we assumed all connection errors were timeouts
    # this should be retried since it could easily be a network glitch
    if type(v) is requests.exceptions.ConnectionError:
        webs_without_ssl.append(k)
    else:
        webs_with_bad_ssl[k] = v

# The ssl error is nested deep in the error stack
# and since we caught the outermost errors, meh
# we deal with the consequence here
ssl_errors = Counter(v.args[0].args[0].args[0] for v in webs_with_bad_ssl.itervalues())

num_webs = len(webs)
num_secure_webs = len(secure_webs)
num_invalid_ssl_webs = sum(ssl_errors.values())
percent_secure = (num_secure_webs * 100.0) / num_webs
percent_invalid = (num_invalid_ssl_webs * 100.0) / (num_secure_webs + num_invalid_ssl_webs)

with open('results/2017/all_domains.txt', 'w') as f:
    f.write("\n".join(subdomain_names))

with open('results/2017/web_domains.txt', 'w') as f:
    f.write("\n".join(webs))

with open('results/2017/secure_web_domains.txt', 'w') as f:
    f.write("\n".join(secure_webs))

with open('results/2017/invalid_secure_web_domains.txt', 'w') as f:
    f.write("\n".join(webs_with_bad_ssl.keys()))

