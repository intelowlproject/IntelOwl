# Usage

## Client
Intel Owl main objective is to provide a single API interface to query in order to retrieve threat intelligence at scale.

There are multiple ways to interact with the Intel Owl APIs,

1. IntelOwl-ng (Web Interface)

    - Inbuilt Web interface with dashboard, visualizations of analysis data, easy to use forms for requesting
    new analysis, tags management and more features
    - [Live Demo](https://intelowlclient.firebaseapp.com/)
    - Built with Angular 9 and available on [Github](https://github.com/intelowlproject/intelowl-ng).

2. pyIntelOwl (CLI/Library) ["How to use" Youtube video](https://www.youtube.com/watch?v=fpd6Kt9EZdI)

    - Official client that is available at: [PyIntelOwl](https://github.com/intelowlproject/pyintelowl),
    - Can be used as a library for your own python projects or...
    - directly via the command line interface.

### Tokens creation
The server authentication is managed by API keys. So, if you want to interact with Intel Owl, you have to create one or more unprivileged users from the Django Admin Interface and then generate a token for those users.
Afterwards you can leverage the created tokens with the Intel Owl Client.

## Available Analyzers

### Get all available analyzers
You can programmatically retrieve all the available analyzers with the official client [PyIntelOwl](https://github.com/intelowlproject/pyintelowl).

### Analyzers list

The following is the list of the available analyzers you can run out-of-the-box:

#### File analyzers:
* `File_Info`: static generic File analysis
* `PDF_Info`: static PDF analysis (peepdf + pdfid)
* `Rtf_Info`: static RTF analysis (Oletools)
* `Doc_Info`: static generic document analysis (Oletools)
* `Doc_Info_Experimental`: static document analysis with new features to analyze XLM macros, encrypted macros and more
* `Xlm_Macro_Deobfuscator`: [XlmMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) deobfuscate xlm macros
* `PE_Info`: static PE analysis (pefile)
* `Signature_Info`: PE signature extractor
* `Speakeasy`: Speakeasy binary emulation
* `Strings_Info_Classic`: strings extraction
* `Strings_Info_ML`: strings extraction plus strings ranking based on Machine Learning. Leverages [Stringsifter](https://github.com/fireeye/stringsifter)
* `VirusTotal_v3_Get_File_And_Scan`: check file hash on VirusTotal. If not already available, send the sample and perform a scan
* `VirusTotal_v3_Get_File`: check only the file hash on VirusTotal (this analyzer is disabled by default to avoid multiple unwanted queries. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `VirusTotal_v2_Get_File`: check file hash on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `VirusTotal_v2_Scan_File`: scan a file on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `Intezer Scan`: scan a file on Intezer
* `Cuckoo_Scan`: scan a file on Cuckoo (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `HybridAnalysis_Get_File`: check file hash on HybridAnalysis sandbox reports
* `OTX_Check_Hash`: check file hash on [Alienvault OTX](https://otx.alienvault.com/)
* `MISP_Check_Hash`: check a file hash on a MISP instance
* `MISPFIRST_Check_Hash`: check a file hash on the FIRST MISP instance
* `Yara_Scan_Community`: scan a file with community yara rules
* `Yara_Scan_Dail_Ioc`: scan a file with StrangerealIntel Daily IOC yara rules
* `Yara_Scan_Florian`: scan a file with Neo23x0 yara rules
* `Yara_Scan_Intezer`: scan a file with Intezer yara rules
* `Yara_Scan_Inquest`: scan a file with Inquest yara rules
* `Yara_Scan_McAfee`: scan a file with McAfee yara rules
* `Yara_Scan_Samir`: scan a file with Samir Threat Hunting yara rules
* `Yara_Scan_Stratosphere`: scan a file with Stratosphere yara rules
* `Yara_Scan_FireEye`: scan a file with FireEye yara rules
* `Yara_Scan_ReversingLabs`: scan a file with ReversingLabs yara rules
* `Yara_Scan_Custom_Signatures`: scan a file with your own added signatures
* `MalwareBazaar_Get_File`: Check if a particular malware sample is known to MalwareBazaar
* `PEframe_Scan`: Perform static analysis on Portable Executable malware and malicious MS Office documents.
* `Cymru_Hash_Registry_Get_File`: Check if a particular file is known to be malware by Team Cymru
* `Thug_HTML_Info`: Perform hybrid dynamic/static analysis on a HTML file using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)
* `Capa_Info`: [Capa](https://github.com/fireeye/capa) detects capabilities in executable files
* `BoxJS_Scan_Javascript`: [Box-JS](https://github.com/CapacitorSet/box-js) is a tool for studying JavaScript malware.
* `APKiD_Scan_APK_DEX_JAR`: [APKiD](https://github.com/rednaga/APKiD) identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file.
* `Quark_Engine_APK`: [Quark Engine](https://github.com/quark-engine/quark-engine) is an Obfuscation-Neglect Android Malware Scoring System.
* `IntelX_Phonebook`: [IntelligenceX](https://intelx.io/) is a search engine and data archive. Fetches emails, urls, domains associated with an observable.
* `UnpacMe_EXE_Unpacker`: [UnpacMe](https://www.unpac.me/) is an automated malware unpacking service
* `Triage_Scan`: leverage [Triage](https://tria.ge) sandbox environment to scan various files
* `Manalyze`: [Manalyze](https://github.com/JusticeRage/Manalyze) performs static analysis on PE executables to detect undesirable behavior.

#### Observable analyzers (ip, domain, url, hash)
* `VirusTotal_v3_Get_Observable`: search an observable in the VirusTotal DB
* `VirusTotal_v2_Get_Observable`: search an observable in the VirusTotal DB using the old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `HybridAnalysis_Get_Observable`: search an observable in the HybridAnalysis sandbox reports
* `OTXQuery`: scan an observable on [Alienvault OTX](https://otx.alienvault.com/)
* `TalosReputation`: check an IP reputation from Talos
* `Stratosphere_Blacklist`: Cross-reference an IP from blacklists maintained by Stratosphere Labs
* `Robtex_Forward_PDNS_Query`: scan a domain against the Robtex Passive DNS DB
* `Robtex_Reverse_PDNS_Query`: scan an IP against the Robtex Passive DNS DB
* `Robtex_IP_Query`: get IP info from Robtex
* `GoogleSafebrowsing`: Scan an observable against GoogleSafeBrowsing DB
* `GreyNoiseAlpha`: scan an IP against the Alpha Greynoise API (no API key required)
* `GreyNoise`: scan an IP against the Greynoise API (requires API key)
* `CIRCLPassiveDNS`: scan an observable against the CIRCL Passive DNS DB
* `CIRCLPassiveSSL`: scan an observable against the CIRCL Passive SSL DB
* `MaxMindGeoIP`: extract GeoIP info for an observable
* `AbuseIPDB`: check if an ip was reported on AbuseIPDB
* `Fortiguard`: scan an observable with the Fortiguard URL Analyzer
* `TorProject`: check if an IP is a Tor Exit Node
* `MISP`: scan an observable on a MISP instance
* `MISPFIRST`: scan an observable on the FIRST MISP instance
* `DNSDB`: scan an observable against the Passive DNS Farsight Database (support both v1 and v2 versions)
* `Shodan_Search`: scan an IP against Shodan Search API
* `Shodan_Honeyscore`: scan an IP against Shodan Honeyscore API
* `HoneyDB_Scan_Twitter`: scan an IP against HoneyDB.io's Twitter Threat Feed
* `HoneyDB_Get`: HoneyDB IP lookup service
* `Hunter`: Scans a domain name and returns set of data about the organisation, the email address found and additional information about the people owning those email addresses.
* `Censys_Search`: scan an IP address against Censys View API
* `MalwareBazaar_Get_Observable`: Check if a particular malware hash is known to MalwareBazaar
* `MalwareBazaar_Google_Observable`: Check if a particular IP, domain or url is known to MalwareBazaar using google search
* `ONYPHE`: search an observable in ONYPHE
* `Threatminer_PDNS`: retrieve PDNS data from Threatminer API
* `Threatminer_Reports_Tagging`: retrieve reports from Threatminer API
* `Threatminer_Subdomains`: retrieve subdomains from Threatminer API
* `URLhaus`: Query a domain or URL against URLhaus API.
* `Google_DNS`: Retrieve current domain resolution with Google DoH (DNS over HTTPS)
* `CloudFlare_DNS`: Retrieve current domain resolution with CloudFlare DoH (DNS over HTTPS)
* `CloudFlare_Malicious_Detector`: Leverages CloudFlare DoH to check if a domain is related to malware
* `Classic_DNS`: Retrieve current domain resolution with default DNS
* `Auth0`: scan an IP against the Auth0 API
* `Securitytrails_IP_Neighbours`: scan an IP against securitytrails API for neighbour IPs
* `Securitytrails_Details`: scan a domain against securitytrails API for general details
* `Securitytrails_Subdomains`: scan a domain against securitytrails API for subdomains
* `Securitytrails_Tags`: scan a domain against securitytrails API for tags
* `Securitytrails_History_WHOIS`: scan a domain against securitytrails API for historical WHOIS
* `Securitytrails_History_DNS`: scan a domain against securitytrails API for historical DNS
* `Cymru_Hash_Registry_Get_Observable`: Check if a particular hash is available in the malware hash registry of Team Cymru
* `Tranco`: Check if a domain is in the latest Tranco ranking top sites list
* `Thug_URL_Info`: Perform hybrid dynamic/static analysis on a URL using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)
* `Pulsedive_Active_IOC`: Scan indicators and retrieve results from [Pulsedive's API](https://pulsedive.com/api/).
* `CheckDMARC`: An SPF and DMARC DNS records validator for domains.
* `Whoisxmlapi`: Fetch WHOIS record data, of a domain name, an IP address, or an email address.
* `UrlScan_Search`: Search an IP/domain/url/hash against [URLScan](https://urlscan.io) API
* `UrlScan_Submit_Result`: Submit & retrieve result of an URL against [URLScan](https://urlscan.io) API
* `Phishtank`: Search an url against [Phishtank](https://phishtank.org/api_info.php) API
* `Quad9_DNS`: Retrieve current domain resolution with Quad9 DoH (DNS over HTTPS)
* `Quad9_Malicious_Detector`: Leverages Quad9 DoH to check if a domain is related to malware
* `DNStwist`: Scan a url/domain to find potentially malicious permutations via dns fuzzing. [dnstwist repo](https://github.com/elceef/dnstwist) 
* `IPInfo`: Location Information about an IP
* `Zoomeye`: [Zoomeye](https://www.zoomeye.org) Cyberspace Search Engine recording information of devices, websites, services and components etc..
* `Triage_Search`: Search for reports of observables or upload from URL on triage cloud
* `InQuest_IOCdb`: Indicators of Compromise Database by [InQuest Labs](https://labs.inquest.net/iocdb)
* `InQuest_REPdb`: Search in [InQuest Lab's](https://labs.inquest.net/repdb) Reputation Database
* `InQuest_DFI`: Deep File Inspection by [InQuest Labs](https://labs.inquest.net/dfi)

#### Generic analyzers (email, phone number, ...)
* `EmailRep`: search an email address on emailrep.io

#### [Additional analyzers](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#optional-analyzers) that can be enabled per your wish.

## Analyzers customization
You can create new analyzers based on already existing modules by changing the configuration values inside `configuration/analyzer_config.json`. This file is mounted as a docker volume, so you won't need to rebuild the image.

The following are all the keys that you can change without touching the source code:
* `disabled`: you can choose to disable certain analyzers, then they won't appear in the dropdown list and won't run if requested.
* `leaks_info`: if set, in the case you specify via the API that a resource is sensitive, the specific analyzer won't be executed
* `external_service`: if set, in the case you specify via the API to exclude external services, the specific analyzer won't be executed
* `supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a different mimetype from the ones you specified, it won't be executed
* `not_supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a mimetype from the ones you specified, it won't be executed
* `observable_supported`: can be populated as a list. If set, if you ask to analyze an observable that is not in this list, it won't be executed. Valid values are: `ip`, `domain`, `url`, `hash`
* `soft_time_limit`: this is the maximum time (in seconds) of execution for an analyzer. Once reached, the task will be killed (or managed in the code by a custom Exception). Default 300s

Also, you can change the name of every available analyzer based on your wishes.

Changing other keys will break the analyzer. In that case, you should think about create a new python module or to modify an existing one.

To contribute to the project, see [Contribute](./Contribute.md)
