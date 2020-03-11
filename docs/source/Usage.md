# Usage

## Client
Intel Owl main objective is to provide a single API interface to query in order to retrieve threat intelligence at scale.

So, in order to interact with the Intel Owl APIs, you may want to use the specific client that is available at: [PyIntelOwl](https://github.com/mlodic/pyintelowl)

We suggest to download the client, read the instructions and use it as a library for your own python projects or directly from the command line.

### Tokens creation
The server authentication is managed by API keys. So, if you want to interact with Intel Owl, you have to create one or more unprivileged users from the Django Admin Interface and then generate a token for those users.
Afterwards you can leverage the created tokens with the Intel Owl Client.


## Available Analyzers

The following is the list of the available analyzers you can run out-of-the-box:

### File analyzers:
* File_Info: static generic File analysis
* PDF_Info: static PDF analysis
* Rtf_Info: static RTF analysis
* Doc_Info: static generic document analysis
* PE_Info: static PE analysis
* Signature_Info: PE signature extractor
* Strings_Info_Classic: strings extraction
* Strings_Info_ML: strings extraction plus strings ranking based on Machine Learning
* VirusTotal_v3_Get_File: check file hash on VirusTotal
* VirusTotal_v3_Get_File_And_Scan: check file hash on VirusTotal. If not already available, perform a scan
* VirusTotal_v3_Scan_File: scan a file on VirusTotal
* VirusTotal_v2_Get_File: check file hash on VirusTotal using old API endpoints
* VirusTotal_v2_Scan_File: scan a file on VirusTotal using old API endpoints
* Intezer Scan: scan a file on Intezer
* Cuckoo_Scan: scan a file on Cuckoo
* HybridAnalysis_Get_File: check file hash on HybridAnalysis
* OTX_Check_Hash: check file hash on OTX Alienvault
* MISP_Check_Hash: check a file hash on a MISP instance
* MISPFIRST_Check_Hash: check a file hash on the FIRST MISP instance
* Yara_Scan_Community: scan a file with community yara rules
* Yara_Scan_Florian: scan a file with Neo23x0 yara rules
* Yara_Scan_Intezer: scan a file with Intezer yara rules
* Yara_Scan_Custom_Signatures: scan a file with your own added signatures


### Observable analyzers (ip, domain, url, hash)
* VirusTotal_v3_Get_Observable: search an observable in the VirusTotal DB
* VirusTotal_v2_Get_Observable: search an observable in the VirusTotal DB using the old API endpoints
* HybridAnalysis_Get_Observable: search an observable in the HybridAnalysis DB
* OTXQuery: scan an observable on Alienvault OTX
* TalosReputation: check an IP reputation from Talos
* Robtex_Forward_PDNS_Query: scan a domain against the Robtex Passive DNS DB
* Robtex_Reverse_PDNS_Query: scan an IP against the Robtex Passive DNS DB
* Robtex_IP_Query: get IP info from Robtex
* GoogleSafebrowsing: scan an observable against GoogleSafeBrowsing DB
* GreyNoiseAlpha: scan an IP against the Alpha Greynoise API
* CIRCLPassiveDNS: scan an observable against the CIRCL Passive DNS DB
* CIRCLPassiveSSL: scan an observable against the CIRCL Passive SSL DB
* MaxMindGeoIP: extract GeoIP info for an observable
* AbuseIPDB: scan an IP against the AbuseIPDB
* Fortiguard: scan an observable with the Fortiguard URL Analyzer
* TorProject: check if an IP is a Tor Exit Node
* MISP: scan an observable on a MISP instance
* MISPFIRST: scan an observable on the FIRST MISP instance
* DNSDB: scan an observable against the Passive DNS Farsight Database
* Shodan: scan an IP against Shodan IP API
* HoneyDB: scan an IP against HoneyDB.io's Twitter Threat Feed
* Hunter: Scans a domain name and returns set of data about the organisation, the email address found and additional information about the people owning those email addresses. 

## Analyzers customization
You can create new analyzers based on already existing modules by changing the configuration values (`analyzer_config.json`).

The following are all the keys that you can change without touching the source code:
* `leaks_info`: if set, in the case you specify via the API that a resource is sensitive, the specific analyzer won't be executed
* `external_service`: if set, in the case you specify via the API to exclude external services, the specific analyzer won't be executed
* `supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a different mimetype from the ones you specified, it won't be executed
* `not_supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a mimetype from the ones you specified, it won't be executed
* `observable_supported`: can be populated as a list. If set, if you ask to analyze an observable that is not in this list, it won't be executed. Valid values are: `ip`, `domain`, `url`, `hash`

Also, you can change the name of every available analyzer based on your wishes.

Changing other keys will break the analyzer. In that case, you should think about create a new python module or to modify an existing one.

To contribute to the project, see [Contribute](./Contribute.md)









