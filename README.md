![Intel Owl](static_intel/intel_owl.jpeg)

[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/intelowlproject/IntelOwl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/intelowlproject/IntelOwl/context:python)
[![CodeFactor](https://www.codefactor.io/repository/github/intelowlproject/intelowl/badge)](https://www.codefactor.io/repository/github/intelowlproject/intelowl)
[![Build Status](https://travis-ci.com/intelowlproject/IntelOwl.svg?branch=master)](https://travis-ci.org/intelowlproject/IntelOwl)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

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
- Official frontend client: **[IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng)** provides features such as dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, etc.

### Documentation

[![Documentation Status](https://readthedocs.org/projects/intelowl/badge/?version=latest)](https://intelowl.readthedocs.io/en/latest/?badge=latest)

Documentation about IntelOwl installation, usage, contribution can be found at https://intelowl.readthedocs.io/.

### Blog posts

[v1.0.0 Announcement](https://www.honeynet.org/?p=7558)

[First announcement](https://www.certego.net/en/news/new-year-new-tool-intel-owl/)

### Free Internal Modules Available

- Static Doc Analysis
- Static RTF Analysis
- Static PDF Analysis
- Static PE Analysis
- Static Generic File Analysis
- Strings analysis
- PE Signature verification

**Free modules that require additional configuration**:

- Cuckoo (requires at least one working Cuckoo instance)
- MISP (requires at least one working MISP instance)
- Yara (Community, Neo23x0, Intezer and McAfee rules are already available. There's the chance to add your own rules)

### External Services Available

##### required paid or trial API key

- GreyNoise v2

##### required paid or free API key

- VirusTotal v2 + v3
- HybridAnalysis
- Intezer
- Farsight DNSDB
- Hunter.io - Email Hunting
- ONYPHE
- Censys.io
- SecurityTrails

##### required free API key

- GoogleSafeBrowsing
- AbuseIPDB
- Shodan
- HoneyDB
- AlienVault OTX
- MaxMind
- Auth0

##### needed access request

- CIRCL PassiveDNS + PassiveSSL

##### without api key

- Fortiguard URL Analyzer
- GreyNoise Alpha API v1
- Talos Reputation
- Tor Project
- Robtex
- Threatminer
- Abuse.ch MalwareBazaar
- Abuse.ch URLhaus
- Team Cymru Malware Hash Registry
- Tranco Rank
- Google DoH
- CloudFlare DoH Classic
- CloudFlare DoH Malware
- Classic DNS resolution

### Legal notice

You as a user of this project must review, accept and comply with the license
terms of each downloaded/installed package listed below. By proceeding with the
installation, you are accepting the license terms of each package, and
acknowledging that your use of each package will be subject to its respective
license terms.

[osslsigncode](https://github.com/develar/osslsigncode),
[stringsifter](https://github.com/fireeye/stringsifter),
[peepdf](https://github.com/jesparza/peepdf),
[oletools](https://github.com/decalage2/oletools),
[MaxMind-DB-Reader-python](https://github.com/maxmind/MaxMind-DB-Reader-python),
[pysafebrowsing](https://github.com/Te-k/pysafebrowsing),
[PyMISP](https://github.com/MISP/PyMISP),
[OTX-Python-SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK),
[yara-python](https://github.com/VirusTotal/yara-python),
[GitPython](https://github.com/gitpython-developers/GitPython),
[Yara community rules](https://github.com/Yara-Rules),
[Neo23x0 Yara sigs](https://github.com/Neo23x0/signature-base),
[Intezer Yara sigs](https://github.com/intezer/yara-rules),
[McAfee Yara sigs](https://github.com/advanced-threat-research/Yara-Rules),
[APKiD](https://github.com/rednaga/APKiD/blob/master/LICENSE.COMMERCIAL),
[Box-JS](https://github.com/CapacitorSet/box-js/blob/master/LICENSE),
[Capa](https://github.com/fireeye/capa/blob/master/LICENSE.txt)

### Acknowledgments

This project was created and will be upgraded thanks to the following organizations:

<img style="margin-right: 2px" src="static_intel/Certego.png" alt="Certego Logo"/>
<img style="border: 0.2px solid black" src="static_intel/logo-thp-100.png" alt="Honeynet.org logo">


### Google Summer Of Code

The project was accepted to the GSoC 2020 under the Honeynet Project!!

Stay tuned for upcoming [new features](https://www.honeynet.org/gsoc/gsoc-2020/google-summer-of-code-2020-project-ideas/#intel-owl-improvements) developed by Eshaan Bansal ([Twitter](https://twitter.com/mask0fmydisguis)).

### About the author

Feel free to contact the author at any time:
Matteo Lodi ([Twitter](https://twitter.com/matte_lodi))


We also have a dedicated twitter account for the project: [@intel_owl](https://twitter.com/intel_owl).
