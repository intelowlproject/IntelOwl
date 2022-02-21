# Usage

## Client
Intel Owl main objective is to provide a single API interface to query in order to retrieve threat intelligence at scale.

There are multiple ways to interact with the Intel Owl APIs,

1. IntelOwl-ng (Web Interface)

    - Inbuilt Web interface with dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, tags management and more features
    - [Live Demo](https://intelowlclient.firebaseapp.com/)
    - Built with Angular 10+ and available on [GitHub](https://github.com/intelowlproject/intelowl-ng).

2. pyIntelOwl (CLI/SDK)

    - Official client that is available at: [PyIntelOwl](https://github.com/intelowlproject/pyintelowl),
    - Can be used as a library for your own python projects or...
    - directly via the command line interface.

<div class="admonition hint">
<p class="admonition-title">Hint: Tokens Creation</p>
The server authentication is managed by API tokens. So, if you want to interact with Intel Owl, you have to create one or more unprivileged users from the Django Admin Interface and then generate a token for those users.
Afterwards you can leverage the created tokens with the Intel Owl Client.
</div>


## Analyzers customization
You can create new analyzers based on already existing modules by changing the configuration values inside `configuration/analyzer_config.json`. This file is mounted as a docker volume, so you won't need to rebuild the image.

You may want to change this configuration to add new analyzers or to change the configuration of some of them. The name of the analyzers can be changed at every moment based on your wishes.

The following are all the keys that you can change without touching the source code:
* `disabled`: you can choose to disable certain analyzers, then they won't appear in the dropdown list and won't run if requested.
* `leaks_info`: if set, in the case you specify via the API that a resource is sensitive, the specific analyzer won't be executed
* `external_service`: if set, in the case you specify via the API to exclude external services, the specific analyzer won't be executed
* `supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a different mimetype from the ones you specified, it won't be executed
* `not_supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a mimetype from the ones you specified, it won't be executed
* `observable_supported`: can be populated as a list. If set, if you ask to analyze an observable that is not in this list, it won't be executed. Valid values are: `ip`, `domain`, `url`, `hash`, `generic`.
* `soft_time_limit`: this is the maximum time (in seconds) of execution for an analyzer. Once reached, the task will be killed (or managed in the code by a custom Exception). Default `300`.
* `queue`: this takes effects only when [multi-queue](Advanced-Usage.html#multi-queue) is enabled. Choose which celery worker would execute the task: `local` (ideal for tasks that leverage local applications like Yara), `long` (ideal for long tasks) or `default` (ideal for simple webAPI-based analyzers).

<div class="admonition hint">
<p class="admonition-title">Hint: Advanced Configuration</p>
You can also modify analyzer specific parameters from the configuration file or even at the time of requesting an analysis. See <a href="./Advanced-Usage.html#customize-analyzer-execution-at-time-of-request">Customize analyzer execution at time of request</a>
</div>

##### Example: add an analyzer configuration for your own Yara signatures
```json
    "Yara_Scan_Custom_Signatures": {
        "type": "file",
        "python_module": "yara_scan.YaraScan",
        "description": "Executes Yara with custom signatures",
        "disabled": false,
        "external_service": false,
        "leaks_info": false,
        "secrets": {},
        "config": {
              "queue": "default",
              "soft_time_limit": 100
        },
        "params": {
              "directories_with_rules": {
              "value": ["/opt/deploy/yara/custom_ruleset"],
              "type": "list",
              "description": ""
            }
        }
    }
```

## Connectors customization
Connectors being optional are `disabled` by default. You can enable them by changing the configuration values inside `configuration/connector_config.json`. This file is mounted as a docker volume, so you won't need to rebuild the image.

The following are all the keys that you can change without touching the source code:
* `disabled`: _similar to analyzers_
* `soft_time_limit`: _similar to analyzers_
* `queue`: _similar to analyzers_
* `maximum_tlp` (default `WHITE`, choices `WHITE`, `GREEN`, `AMBER`, `RED`): specify with the maximum TLP of the analysis upto which the connector is allowed to run. (e.g. if `maximum_tlp` is `GREEN`, it would run for analysis with TLPs `WHITE` and `GREEN`). To learn more about TLPs see [TLP Support](./Usage.md#tlp-support).

<div class="admonition warning">
<p class="admonition-title">Warning</p>
Changing other keys can break an analyzer or connector. In that case, you should think about duplicating the configuration entry or python module with your changes.
</div>


## Managing Analyzers and Connectors
All plugins i.e. analyzers and connectors have `kill` and `retry` actions. In addition to that, all docker-based analyzers and connectors have a `healthcheck` action to check if their associated instances are up or not. 

- **kill:**

   To stop a plugin whose status is `running`/`pending`: 
   * GUI: Buttons on reports table on job result page.
   * PyIntelOwl: `IntelOwl.kill_analyzer` and `IntelOwl.kill_connector` function.
   * CLI: `$ pyintelowl jobs kill-analyzer <job_id> <analyzer_name>` and `$ pyintelowl jobs kill-connector <job_id> <connector_name>`
   * API: `PATCH /api/job/{job_id}/analyzer/{analyzer_name}/kill` and `PATCH /api/job/{job_id}/connector/{connector_name}/kill`
- **retry:**

   To retry a plugin whose status is `failed`/`killed`: 
   * GUI: Buttons on reports table on job result page.
   * PyIntelOwl: `IntelOwl.retry_analyzer` and `IntelOwl.retry_connector` function,
   * CLI: `$ pyintelowl jobs retry-analyzer <job_id> <analyzer_name>` and `$ pyintelowl jobs retry-connector <job_id> <connector_name>`
   * API: `PATCH /api/job/{job_id}/analyzer/{analyzer_name}/retry` and `PATCH /api/job/{job_id}/connector/{connector_name}/retry`
- **healthcheck:**

   To check if docker container or external platform associated with an analyzer or connector respectively are up or not: 
   * GUI: Buttons on analyzers table and connectors table.
   * PyIntelOwl: `IntelOwl.analyzer_healthcheck` and `IntelOwl.connector_healthcheck` methods.
   * CLI: `$ pyintelowl analyzer-healthcheck <analyzer_name>` and `$ pyintelowl connector-healthcheck <connector_name>`
   * API: `GET /api/analyzer/{analyzer_name}/healthcheck` and `GET /api /connector/{connector_name}/healthcheck`


## TLP Support
IntelOwl supports the **Traffic Light Protocol** (TLP) to facilitate sharing of job analysis results.

Following are the indicators available when requesting an analysis (in the order of increasing sharing restrictions):
1. `WHITE`: no restriction
2. `GREEN`: disable analyzers that could impact privacy
3. `AMBER`: disable analyzers that could impact privacy and limit view permissions to my group
4. `RED`: disable analyzers that could impact privacy, limit view permissions to my group and do not use any external service

These indicators when used with `maximum_tlp` (option available in connectors), give you the control of what information is shared to the external platforms.


## Available Analyzers

### Analyzers list
The following is the list of the available analyzers you can run out-of-the-box. You can also navigate the same list via the,

- [live demo](https://intelowlclient.firebaseapp.com/pages/analyzers/table) for better UX.
- [pyintelowl](https://github.com/intelowlproject/pyintelowl): `$ pyintelowl get-analyzer-config`

##### File analyzers:

* `File_Info`: static generic File analysis (hashes, magic and [exiftool](https://exiftool.org/))
* `PDF_Info`: static PDF analysis ([peepdf](https://github.com/jesparza/peepdf) + [pdfid](https://github.com/mlodic/pdfid))
* `Rtf_Info`: static RTF analysis ([Oletools](https://github.com/decalage2/oletools))
* `Doc_Info`: static generic document analysis ([Oletools](https://github.com/decalage2/oletools))
* `Xlm_Macro_Deobfuscator`: [XlmMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) deobfuscate xlm macros
* `Doc_Info_Experimental`: static document analysis with new features to analyze XLM macros, encrypted macros and more (combination of Oletools and XLMMacroDeobfuscator)
* `PE_Info`: static PE analysis with [pefile](https://github.com/mlodic/pefile)
* `Signature_Info`: PE signature extractor with [osslsigncode](https://github.com/mtrojnar/osslsigncode)
* `Speakeasy`: [FireEye Speakeasy](https://github.com/fireeye/speakeasy) binary emulation
* `Strings_Info_Classic`: strings extraction
* `Strings_Info_ML`: strings extraction plus strings ranking based on Machine Learning. Leverages [Stringsifter](https://github.com/fireeye/stringsifter)
* `VirusTotal_v3_Get_File_And_Scan`: check file hash on VirusTotal. If not already available, send the sample and perform a scan
* `VirusTotal_v3_Get_File`: check only the file hash on VirusTotal (this analyzer is disabled by default to avoid multiple unwanted queries. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `VirusTotal_v2_Get_File`: check file hash on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `VirusTotal_v2_Scan_File`: scan a file on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `Intezer Scan`: scan a file on [Intezer](https://analyze.intezer.com/?utm_source=IntelOwl). Register for a free community account [here](https://analyze.intezer.com/sign-in?utm_source=IntelOwl)
* `Cuckoo_Scan`: scan a file on Cuckoo (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `HybridAnalysis_Get_File`: check file hash on [HybridAnalysis](https://www.hybrid-analysis.com/) sandbox reports
* `OTX_Check_Hash`: check file hash on [Alienvault OTX](https://otx.alienvault.com/)
* `MISP_Check_Hash`: check a file hash on a MISP instance
* `MISPFIRST_Check_Hash`: check a file hash on the FIRST MISP instance
* `Yara_Scan_ATM_MALWARE`: scan a file with the [ATM malware yara rules](https://github.com/fboldewin/YARA-rules)
* `Yara_Scan_Community`: scan a file with the [community yara rules](https://github.com/Yara-Rules/rules)
* `Yara_Scan_Dail_Ioc`: scan a file with [StrangerealIntel](https://github.com/StrangerealIntel) Daily IOC yara rules
* `Yara_Scan_Florian`: scan a file with [Neo23x0 yara rules](https://github.com/Neo23x0/signature-base)
* `Yara_Scan_Intezer`: scan a file with [Intezer yara rules](https://github.com/intezer/yara-rules)
* `Yara_Scan_Inquest`: scan a file with [Inquest yara rules](https://github.com/InQuest/yara-rules)
* `Yara_Scan_McAfee`: scan a file with [McAfee yara rules](https://github.com/advanced-threat-research/Yara-Rules)
* `Yara_Scan_Samir`: scan a file with [Samir Threat Hunting yara rules](https://github.com/sbousseaden/YaraHunts)
* `Yara_Scan_Stratosphere`: scan a file with [Stratosphere yara rules](https://github.com/stratosphereips/yara-rules)
* `Yara_Scan_FireEye`: scan a file with FireEye yara rules
* `Yara_Scan_ReversingLabs`: scan a file with [ReversingLabs yara rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
* `Yara_Scan_Custom_Signatures`: scan a file with your own added signatures
* `MalwareBazaar_Get_File`: Check if a particular malware sample is known to [MalwareBazaar](https://bazaar.abuse.ch/)
* `PEframe_Scan`: Perform static analysis on Portable Executable malware and malicious MS Office documents with [PeFrame](https://github.com/guelfoweb/peframe)
* `Cymru_Hash_Registry_Get_File`: Check if a particular file is known to be malware by [Team Cymru](https://team-cymru.com/community-services/mhr/)
* `Thug_HTML_Info`: Perform hybrid dynamic/static analysis on a HTML file using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)
* `CapeSandbox`: [CAPESandbox](https://capesandbox.com) automatically scans suspicious files using the CapeSandbox API. Analyzer works for private instances as well.
* `Capa_Info`: [Capa](https://github.com/fireeye/capa) detects capabilities in executable files
* `BoxJS_Scan_Javascript`: [Box-JS](https://github.com/CapacitorSet/box-js) is a tool for studying JavaScript malware.
* `APKiD_Scan_APK_DEX_JAR`: [APKiD](https://github.com/rednaga/APKiD) identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file.
* `Quark_Engine_APK`: [Quark Engine](https://github.com/quark-engine/quark-engine) is an Obfuscation-Neglect Android Malware Scoring System.
* `IntelX_Phonebook`: [IntelligenceX](https://intelx.io/) is a search engine and data archive. Fetches emails, urls, domains associated with an observable.
* `UnpacMe_EXE_Unpacker`: [UnpacMe](https://www.unpac.me/) is an automated malware unpacking service
* `Triage_Scan`: leverage [Triage](https://tria.ge) sandbox environment to scan various files
* `Manalyze`: [Manalyze](https://github.com/JusticeRage/Manalyze) performs static analysis on PE executables to detect undesirable behavior.
* `MWDB_Scan`: [mwdblib](https://mwdb.readthedocs.io/en/latest/) Retrieve malware file analysis from repository maintained by CERT Polska MWDB.
* `Qiling`: [Qiling](https://github.com/qilingframework/qiling) qiling binary emulation.
* `Malpedia_Scan`: scan a binary or a zip file (pwd:infected) against all the yara rules available in [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
* `HashLookupServer_Get_File`: check if a md5 or sha1 is available in the database of [known file hosted by CIRCL](https://github.com/adulau/hashlookup-server)
* `FileScan_Upload_File`: Upload your file to extract IoCs from executable files, documents and scripts via [FileScan.io API](https://www.filescan.io/api/docs).
* `Dragonfly_Emulation`: Emulate malware against [Dragonfly](https://dragonfly.certego.net?utm_source=intelowl) sandbox by [Certego S.R.L](https://certego.net?utm_source=intelowl).
* `Virushee_UploadFile`: Check file hash and upload file sample for analysis on [Virushee API](https://api.virushee.com/).

##### Observable analyzers (ip, domain, url, hash)
* `VirusTotal_v3_Get_Observable`: search an observable in the VirusTotal DB
* `VirusTotal_v2_Get_Observable`: search an observable in the VirusTotal DB using the old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config]((https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)) to use it)
* `HybridAnalysis_Get_Observable`: search an observable in the [HybridAnalysis](https://www.hybrid-analysis.com/) sandbox reports
* `OTXQuery`: scan an observable on [Alienvault OTX](https://otx.alienvault.com/)
* `TalosReputation`: check an IP reputation from [Talos](https://talosintelligence.com/reputation_center/)
* `Stratosphere_Blacklist`: Cross-reference an IP from blacklists maintained by [Stratosphere Labs](https://www.stratosphereips.org/attacker-ip-prioritization-blacklist)
* `BitcoinAbuse` : Check a BTC address against bitcoinabuse.com, a public database of BTC addresses used by hackers and criminals.
* `Robtex_Forward_PDNS_Query`: scan a domain against the Robtex Passive DNS DB
* `Robtex_Reverse_PDNS_Query`: scan an IP against the Robtex Passive DNS DB
* `Robtex_IP_Query`: get IP info from Robtex
* `GoogleSafebrowsing`: Scan an observable against GoogleSafeBrowsing DB
* `GoogleWebRisk`: Scan an observable against WebRisk API (Commercial version of Google Safe Browsing). Check the [docs](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#analyzers-with-special-configuration) to enable this properly
* `GreyNoiseCommunity`: scan an IP against the [Community Greynoise API](https://www.greynoise.io/) (no API key required)
* `GreyNoise`: scan an IP against the [Greynoise](https://www.greynoise.io/) API (requires API key)
* `CIRCLPassiveDNS`: scan an observable against the CIRCL Passive DNS DB
* `CIRCLPassiveSSL`: scan an observable against the CIRCL Passive SSL DB
* `MaxMindGeoIP`: extract GeoIP info for an observable
* `AbuseIPDB`: check if an ip was reported on [AbuseIPDB](https://www.abuseipdb.com/)
* `Fortiguard`: scan an observable with the [Fortiguard URL Analyzer](https://www.fortiguard.com/webfilter)
* `TorProject`: check if an IP is a Tor Exit Node
* `MISP`: scan an observable on a MISP instance
* `MISPFIRST`: scan an observable on the FIRST MISP instance
* `DNSDB`: scan an observable against the [Passive DNS Farsight Database](https://www.farsightsecurity.com/solutions/dnsdb/) (support both v1 and v2 versions)
* `Shodan_Search`: scan an IP against [Shodan](https://www.shodan.io/) Search API
* `Shodan_Honeyscore`: scan an IP against [Shodan](https://www.shodan.io/) Honeyscore API
* `HoneyDB_Get`: [HoneyDB](https://honeydb.io/) IP lookup service
* `HoneyDB_Scan_Twitter`: scan an IP against HoneyDB.io's Twitter Threat Feed
* `Hunter`: Scans a domain name and returns set of data about the organisation, the email address found and additional information about the people owning those email addresses.
* `Censys_Search`: scan an IP address against [Censys](https://censys.io/) View API
* `MalwareBazaar_Get_Observable`: Check if a particular malware hash is known to [MalwareBazaar](https://bazaar.abuse.ch/)
* `MalwareBazaar_Google_Observable`: Check if a particular IP, domain or url is known to MalwareBazaar using google search
* `ONYPHE`: search an observable in [ONYPHE](https://www.onyphe.io/)
* `Threatminer_PDNS`: retrieve PDNS data from [Threatminer](https://www.threatminer.org/) API
* `Threatminer_Reports_Tagging`: retrieve reports from Threatminer API
* `Threatminer_Subdomains`: retrieve subdomains from Threatminer API
* `URLhaus`: Query a domain or URL against [URLhaus](https://urlhaus.abuse.ch/) API.
* `Google_DNS`: Retrieve current domain resolution with Google DoH (DNS over HTTPS)
* `CloudFlare_DNS`: Retrieve current domain resolution with CloudFlare DoH (DNS over HTTPS)
* `CloudFlare_Malicious_Detector`: Leverages CloudFlare DoH to check if a domain is related to malware
* `Classic_DNS`: Retrieve current domain resolution with default DNS
* `Auth0`: scan an IP against the Auth0 API
* `Securitytrails_IP_Neighbours`: scan an IP against [Securitytrails](https://securitytrails.com/) API for neighbour IPs
* `Securitytrails_Details`: scan a domain against Securitytrails API for general details
* `Securitytrails_Subdomains`: scan a domain against Securitytrails API for subdomains
* `Securitytrails_Tags`: scan a domain against Securitytrails API for tags
* `Securitytrails_History_WHOIS`: scan a domain against Securitytrails API for historical WHOIS
* `Securitytrails_History_DNS`: scan a domain against Securitytrails API for historical DNS
* `Cymru_Hash_Registry_Get_Observable`: Check if a particular hash is available in the malware hash registry of [Team Cymru](https://team-cymru.com/community-services/mhr/)
* `Tranco`: Check if a domain is in the latest [Tranco](https://tranco-list.eu/) ranking top sites list
* `Thug_URL_Info`: Perform hybrid dynamic/static analysis on a URL using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)
* `Pulsedive_Active_IOC`: Scan indicators and retrieve results from [Pulsedive's API](https://pulsedive.com/api/).
* `CheckDMARC`: An SPF and DMARC DNS records validator for domains.
* `Whoisxmlapi`: Fetch WHOIS record data, of a domain name, an IP address, or an email address.
* `WhoIs_RipeDB_Search` : Fetch whois record data of an IP address from Ripe DB using their [search API](https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-search) (no API key required)
* `UrlScan_Search`: Search an IP/domain/url/hash against [URLScan](https://urlscan.io) API
* `UrlScan_Submit_Result`: Submit & retrieve result of an URL against [URLScan](https://urlscan.io) API
* `Mnemonic_PassiveDNS` : Look up a domain or IP using the [Mnemonic PassiveDNS public API](https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview).
* `Phishtank`: Search an url against [Phishtank](https://phishtank.org/api_info.php) API
* `Phishstats`: Search [PhishStats API](https://phishstats.info/) to determine if an IP/URL/domain is malicious.
* `Quad9_DNS`: Retrieve current domain resolution with Quad9 DoH (DNS over HTTPS)
* `Quad9_Malicious_Detector`: Leverages Quad9 DoH to check if a domain is related to malware
* `DNStwist`: Scan a url/domain to find potentially malicious permutations via dns fuzzing. [dnstwist repo](https://github.com/elceef/dnstwist) 
* `IPInfo`: Location Information about an IP
* `Zoomeye`: [Zoomeye](https://www.zoomeye.org) Cyberspace Search Engine recording information of devices, websites, services and components etc..
* `Triage_Search`: Search for reports of observables or upload from URL on triage cloud
* `InQuest_IOCdb`: Indicators of Compromise Database by [InQuest Labs](https://labs.inquest.net/iocdb)
* `InQuest_REPdb`: Search in [InQuest Lab's](https://labs.inquest.net/repdb) Reputation Database
* `InQuest_DFI`: Deep File Inspection by [InQuest Labs](https://labs.inquest.net/dfi)
* `XForceExchange`: scan an observable on [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
* `Renderton`: get screenshot of a web page using rendertron (puppeteer) [renderton repo](https://github.com/GoogleChrome/rendertron)
* `SSAPINet`: get a screenshot of a web page using [screenshotapi.net](https://screenshotapi.net/) (external source); additional config options can be added to `extra_api_params` [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json).
* `FireHol_IPList`: check if an IP is in [FireHol's IPList](https://iplists.firehol.org/)
* `ThreatFox`: search for an IOC in [ThreatFox](https://threatfox.abuse.ch/api/)'s database
* `OpenCTI`: scan an observable on an [OpenCTI](https://github.com/OpenCTI-Platform/opencti) instance
* `Intezer_Get`: check if an analysis related to a hash is available in [Intezer](https://analyze.intezer.com/?utm_source=IntelOwl). Register for a free community account [here](https://analyze.intezer.com/sign-in).
* `MWDB_Get`: [mwdblib](https://mwdb.readthedocs.io/en/latest/) Retrieve malware file analysis by hash from repository maintained by CERT Polska MWDB.
* `YETI` (Your Everyday Threat Intelligence): scan an observable on a [YETI](https://github.com/yeti-platform/yeti) instance.
* `HashLookupServer_Get_Observable`: check if a md5 or sha1 is available in the database of [known file hosted by CIRCL](https://github.com/adulau/hashlookup-server)
* `ClamAV`: scan a file via the [ClamAV AntiVirus Engine](https://www.clamav.net/)
* `Spyse`: Scan domains, IPs, emails and CVEs using Spyse's API. Register [here](https://spyse.com/user/registration).
* `FileScan_Search`: Finds reports and uploaded files by various tokens, like hash, filename, verdict, IOCs etc via [FileScan.io  API](https://www.filescan.io/api/docs).
* `Virushee_CheckHash`: Search for a previous analysis of a file by its hash (SHA256/SHA1/MD5) on [Virushee API](https://api.virushee.com/).

##### Generic analyzers (email, phone number, etc.; anything really)
Some analyzers require details other than just IP, URL, Domain, etc. We classified them as `generic` Analyzers. Since the type of field is not known, there is a format for strings to be followed.
* `EmailRep`: search an email address on emailrep.io
* `WiGLE`: Maps and database of 802.11 wireless networks, with statistics, submitted by wardrivers, netstumblers, and net huggers.
* `CRXcavator`: scans a chrome extension against crxcavator.io
* `Darksearch_Query`: Search a keyword against darksearch.io's search API. It's possible to make complex queries using boolean logic. For example, `OSINT AND CTI OR intelowl NOT hack` is a valid observable name.
* `Dehashed_Search`: Query any observable/keyword against https://dehashed.com's search API.
* `CryptoScamDB_CheckAPI`: Scan a cryptocurrency address, IP address, domain or ENS name against the [CryptoScamDB](https://cryptoscamdb.org/) API.

##### Extra analyzers
[Additional analyzers](Advanced-Usage.html#optional-analyzers) that can be enabled per your wish.


## Available Connectors
Connectors are designed to run after every successful analysis which makes them suitable for automated threat-sharing. They support integration with other SIEM/SOAR projects, specifically aimed at Threat Sharing Platforms.

### Connectors list
The following is the list of the available connectors. You can also navigate the same list via the,

- [live demo](https://intelowlclient.firebaseapp.com/pages/connectors/table) for better UX.
- [pyintelowl](https://github.com/intelowlproject/pyintelowl): `$ pyintelowl get-connector-config`


* `MISP`: automatically creates an event on your MISP instance, linking the successful analysis on IntelOwl.
* `OpenCTI`: automatically creates an observable and a linked report on your OpenCTI instance, linking the the successful analysis on IntelOwl.
* `YETI`: YETI = Your Everyday Threat Intelligence. find or create observable on YETI, linking the successful analysis on IntelOwl.

--------------------

To contribute to the project, see [Contribute](./Contribute.md).
