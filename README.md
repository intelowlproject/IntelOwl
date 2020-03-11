![Intel Owl](static_intel/intel_owl.jpeg)


[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/certego/IntelOwl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/certego/IntelOwl/context:python)
# Intel Owl

Do you want to get **threat intelligence data** about a file, an IP or a domain?

Do you want to get this kind of data from multiple sources at the same time using **a single API request**?

You are in the right place!

This application is built to **scale out** and to **speed up the retrieval of threat info**.

It can be integrated easily in your stack of security tools to automate common jobs usually performed, for instance, by SOC analysts manually.

Intel Owl is composed of **analyzers** that can be run to retrieve data from external sources (like VirusTotal or AbuseIPDB) or to generate intel from internal analyzers (like Yara or Oletools)

This solution is for everyone who needs a single point to query for info about a specific file or observable (domain, IP, URL, hash).

Main features:
- full django-python application
- easily and completely customizable, both the APIs and the analyzers
- clone the project, set up the configuration and you are ready to run

### Free internal modules available
* Static Doc Analysis
* Static RTF Analysis
* Static PDF Analysis
* Static PE Analysis
* Static Generic File Analysis
* Strings analysis
* PE Signature verification

### Free modules that require additional configuration
* Cuckoo (requires at least one working Cuckoo instance)
* MISP (requires at least one working MISP instance)
* Yara (Community, Neo23x0 and Intezer rules are already available. There's the chance to add your own rules)

### External services available
#### required paid or free api key
* VirusTotal v2 + v3
* HybridAnalysis
* Intezer
* Farsight DNSDB
* Hunter.io - Email Hunting
#### required free api key
* GoogleSafeBrowsing
* AbuseIPDB
* Shodan
* HoneyDB - Twitter Threat Feed Scan and Nodes scan
* AlienVault OTX
* MaxMind
#### needed access request
* CIRCL PassiveDNS + PassiveSSL
#### without api key
* Fortiguard URL Analyzer
* GreyNoise Alpha API
* Talos Reputation
* Tor Project
* Robtex

### Documentation
[![Documentation Status](https://readthedocs.org/projects/intelowl/badge/?version=latest)](https://intelowl.readthedocs.io/en/latest/?badge=latest)

Documentation about IntelOwl installation and usage can be found at https://intelowl.readthedocs.io/.


### Legal notice
You as a user of this project must review, accept and comply with the license
terms of each downloaded/installed package listed below. By proceeding with the
installation, you are accepting the license terms of each package, and
acknowledging that your use of each package will be subject to its respective
license terms.

osslsigncode: https://github.com/develar/osslsigncode

stringsifter: https://github.com/fireeye/stringsifter

peepdf: https://github.com/jesparza/peepdf

oletools: https://github.com/decalage2/oletools

MaxMind-DB-Reader-python: https://github.com/maxmind/MaxMind-DB-Reader-python

pysafebrowsing: https://github.com/Te-k/pysafebrowsing

PyMISP: https://github.com/MISP/PyMISP

OTX-Python-SDK: https://github.com/AlienVault-OTX/OTX-Python-SDK

yara-python: https://github.com/VirusTotal/yara-python

GitPython: https://github.com/gitpython-developers/GitPython

Yara community rules: https://github.com/Yara-Rules

Neo23x0 Yara sigs: https://github.com/Neo23x0/signature-base

Intezer Yara sigs: https://github.com/intezer/yara-rules

### About the author 
Feel free to contact the author at any time:
Matteo Lodi [Twitter](https://twitter.com/matte_lodi)

