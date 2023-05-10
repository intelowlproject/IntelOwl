# Usage

This page includes the most important things to know and understand when using IntelOwl.

- [Client](#client)
- [Organizations and User Management](#organizations-and-user-management)
  - [Multi Tenancy](#multi-tenancy)
  - [Registration](#registration)
- [TLP Support](#tlp-support)
- [Plugins](#plugins)
  - [Analyzers](#analyzers)
  - [Connectors](#connectors)
  - [Managing Analyzers and Connectors](#managing-analyzers-and-connectors)
  - [Visualizers](#visualizers)
  - [Playbooks](#playbooks)

## Client

Intel Owl main objective is to provide a single API interface to query in order to retrieve threat intelligence at scale.

There are multiple ways to interact with the Intel Owl APIs,

1. Web Interface

   - Built-in Web interface with dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, tags management and more features
   - Built with [Create React App](https://create-react-app.dev/) and based on [certego-ui](https://github.com/certego/certego-ui).

2. pyIntelOwl (CLI/SDK)

   - Official Python client that is available at: [PyIntelOwl](https://github.com/intelowlproject/pyintelowl),
   - Can be used as a library for your own python projects or...
   - directly via the command line interface.

3. goIntelOwl (CLI/SDK)
   - Official GO client that is available at: [go-intelowl](https://github.com/intelowlproject/go-intelowl)

<div class="admonition hint">
<p class="admonition-title">Hint: Tokens Creation</p>
The server authentication is managed by API tokens. So, if you want to interact with Intel Owl, you have two ways to do that:
<ul>
<li>If you are a normal user, you can go to the "API Access/Sessions" section of the GUI and create a Token there.</li>
<li>If you are an administrator of IntelOwl, you can create one or more unprivileged users from the Django Admin Interface and then generate a token for those users.
</li>
</ul>
Afterwards you can leverage the created tokens with the Intel Owl Client.
</div>

## Organizations and User management

Starting from IntelOwl v4, a new "Organization" section is available on the GUI. This section substitute the previous permission management via Django Admin and aims to provide an easier way to manage users and visibility.

### Multi Tenancy

Thanks to the "Organization" feature, IntelOwl can be used by multiple SOCs, companies, etc...very easily.
Right now it works very simply: only users in the same organization can see analysis of one another. An user can belong to an organization only.

#### Manage organizations

You can create a new organization by going to the "Organization" section, available under the Dropdown menu you cand find under the username.

Once you create an organization, you are the unique Administrator of that organization. So you are the only one who can delete the organization, remove users and send invitations to other users.

#### Accept Invites

Once an invite has sent, the invited user has to login, go to the "Organization" section and accept the invite there. Afterwards the Administrator will be able to see the user in his "Organization" section.

#### Plugins Params and Secrets

From IntelOwl v4.1.0, Plugin Parameters and Secrets can be defined at the organization level, in the dedicated section.
This allows to share configurations between users of the same org while allowing complete multi-tenancy of the application.

#### Disable Analyzers at Org level

From IntelOwl v4.1.0, the org admin can disable specific analyzers for all the users in a specific org.
To do that, org admins needs to go in the "Plugins" section and click the button "Enabled for organization" of the analyzer that they want to disable.

### Registration
Since IntelOwl v4.2.0 we added a Registration Page that can be used to manage Registration requests when providing IntelOwl as a Service.

After a user registration has been made, an email is sent to the user to verify their email address. If necessary, there are buttons on the login page to resend the verification email and to reset the password.

Once the user has verified their email, they would be manually vetted before being allowed to use the IntelOwl platform. The registration requests would be handled in the Django Admin page by admins.
If you have IntelOwl deployed on an AWS instance with an IAM role you can use the [SES](/Advanced-Usage.md#ses) service.

To have the "Registration" page to work correctly, you must configure some variables before starting IntelOwl. See [Optional Environment Configuration](/Installation.md#other-optional-configuration-to-enable-specific-services-features)

In a development environment the emails that would be sent are written to the standard output.

#### Recaptcha configuration
The Registration Page contains a Recaptcha form from Google. By default, that Recaptcha is not configured and is not shown.

If your intention is to publish IntelOwl as a Service you should first remember to comply to the [AGPL License](https://github.com/intelowlproject/IntelOwl/blob/master/LICENSE), then you should configure the Recaptcha Key for your site and add that value in the `RECAPTCHA_SITEKEY` in the `docker/env_template.js` file.
In that case, you would need to [re-build](/Installation.md#update-and-rebuild) the application to have the changes properly reflected.


## TLP Support

IntelOwl supports the **Traffic Light Protocol** (TLP) to facilitate sharing of job analysis results.

Following are the indicators available when requesting an analysis (in the order of increasing sharing restrictions):

1. `CLEAR`: no restriction (`WHITE` was replaced by `CLEAR` in TLP v2.0, but `WHITE` is supported for retrocompatibility)
2. `GREEN`: disable analyzers that could impact privacy
3. `AMBER`: disable analyzers that could impact privacy and limit view permissions to my group
4. `RED`: disable analyzers that could impact privacy, limit view permissions to my group and do not use any external service

These indicators when used with `maximum_tlp` (option available in connectors), give you the control of what information is shared to the external platforms.

## Plugins

Plugins are the core modular components of IntelOwl that can be easily added, changed and customized.
There are 3 types of plugins:

- [Analyzers](#analyzers)
- [Connectors](#connectors)
- [Visualizers](#visualizers)
- [Playbooks](#playbooks)

### Analyzers

Analyzers are the most important plugins in IntelOwl. They allow to perform data extraction on the observables and/or files that you would like to analyze.

#### Analyzers list

The following is the list of the available analyzers you can run out-of-the-box. You can also navigate the same list via the

- Graphical Interface: once your application is up and running, go to the "Plugins" section
- [pyintelowl](https://github.com/intelowlproject/pyintelowl): `$ pyintelowl get-analyzer-config`

##### File analyzers:

###### Internal tools
* `APKiD`: [APKiD](https://github.com/rednaga/APKiD) identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file.
* `BoxJS_Scan_Javascript`: [Box-JS](https://github.com/CapacitorSet/box-js) is a tool for studying JavaScript malware.
* `Capa_Info`: [Capa](https://github.com/mandiant/capa) detects capabilities in executable files
* `Capa_Info_Shellcode`: [Capa](https://github.com/mandiant/capa) detects capabilities in shellcode
* `ClamAV`: scan a file via the [ClamAV AntiVirus Engine](https://www.clamav.net/). IntelOwl automatically keep ClamAV updated with official and [unofficial](https://github.com/rseichter/fangfrisch) open source signatures
* `Doc_Info`: static document analysis with new features to analyze XLM macros, encrypted macros and more (combination of Oletools and XLMMacroDeobfuscator)
* `ELF_Info`: static ELF analysis with [pyelftools](https://github.com/eliben/pyelftools) and [telfhash](https://github.com/trendmicro/telfhash)
* `File_Info`: static generic File analysis (hashes, magic and [exiftool](https://exiftool.org/))
* `Floss`: [Mandiant Floss](https://github.com/mandiant/flare-floss) Obfuscated String Solver in files
* `PE_Info`: static PE analysis with [pefile](https://github.com/mlodic/pefile)
* `PEframe_Scan`: Perform static analysis on Portable Executable malware and malicious MS Office documents with [PeFrame](https://github.com/guelfoweb/peframe)
* `PDF_Info`: static PDF analysis ([peepdf](https://github.com/jesparza/peepdf) + [pdfid](https://github.com/mlodic/pdfid))
* `Qiling_Linux`: [Qiling](https://github.com/qilingframework/qiling) qiling linux binary emulation.
* `Qiling_Linux_Shellcode`: [Qiling](https://github.com/qilingframework/qiling) qiling linux shellcode emulation.
* `Qiling_Windows`: [Qiling](https://github.com/qilingframework/qiling) qiling windows binary emulation.
* `Qiling_Windows_Shellcode`: [Qiling](https://github.com/qilingframework/qiling) qiling windows shellcode emulation.
* `Quark_Engine`: [Quark Engine](https://github.com/quark-engine/quark-engine) is an Obfuscation-Neglect Android Malware Scoring System.
* `Rtf_Info`: static RTF analysis ([Oletools](https://github.com/decalage2/oletools))
* `Signature_Info`: PE signature extractor with [osslsigncode](https://github.com/mtrojnar/osslsigncode)
* `Speakeasy`: [Mandiant Speakeasy](https://github.com/mandiant/speakeasy) binary emulation
* `SpeakEasy_Shellcode`: [Mandiant Speakeasy](https://github.com/mandiant/speakeasy) shellcode emulation
* `Strings_Info`: Strings extraction. Leverages Mandiant's [Stringsifter](https://github.com/mandiant/stringsifter)
* `Suricata`: Analyze PCAPs with open IDS signatures with [Suricata engine](https://github.com/OISF/suricata)
* `Thug_HTML_Info`: Perform hybrid dynamic/static analysis on a HTML file using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)
* `Xlm_Macro_Deobfuscator`: [XlmMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) deobfuscate xlm macros
* `Yara`: scan a file with
  * [ATM malware yara rules](https://github.com/fboldewin/YARA-rules)
  * [bartblaze yara rules](https://github.com/bartblaze/Yara-rules)
  * [community yara rules](https://github.com/Yara-Rules/rules)
  * [StrangerealIntel](https://github.com/StrangerealIntel) 
  * [Neo23x0 yara rules](https://github.com/Neo23x0/signature-base)
  * [Intezer yara rules](https://github.com/intezer/yara-rules)
  * [Inquest yara rules](https://github.com/InQuest/yara-rules)
  * [McAfee yara rules](https://github.com/advanced-threat-research/Yara-Rules)
  * [Samir Threat Hunting yara rules](https://github.com/sbousseaden/YaraHunts)
  * [Stratosphere yara rules](https://github.com/stratosphereips/yara-rules)
  * [Mandiant yara rules](https://github.com/mandiant/red_team_tool_countermeasures)
  * [ReversingLabs yara rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
  * [YARAify rules](https://yaraify.abuse.ch/api/#download-yara-package)
  * [SIFalcon rules](https://github.com/SIFalcon/Detection/)
  * [Elastic rules](https://github.com/elastic/protections-artifacts)
  * [JPCERTCC Yara rules](https://github.com/JPCERTCC/jpcert-yara)
  * [HuntressLab Yara rules](https://github.com/embee-research/Yara)
  * [elceef Yara Rules](https://github.com/elceef/yara-rulz)
  * [dr4k0nia Yara rules](https://github.com/dr4k0nia/yara-rules)
  * your own added signatures. See [Advanced-Usage](./Advanced-Usage.html#analyzers-with-special-configuration) for more details.

###### External services

- `CapeSandbox`: [CAPESandbox](https://capesandbox.com) automatically scans suspicious files using the CapeSandbox API. Analyzer works for private instances as well.
- `Cymru_Hash_Registry_Get_File`: Check if a particular file is known to be malware by [Team Cymru](https://team-cymru.com/community-services/mhr/)
- `Cuckoo_Scan`: scan a file on Cuckoo (this analyzer is disabled by default. You have to change that flag [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) to use it)
- `DocGuard_Upload_File`: Analyze office files in seconds. [DocGuard](https://www.docguard.io).
- `Dragonfly_Emulation`: Emulate malware against [Dragonfly](https://dragonfly.certego.net?utm_source=intelowl) sandbox by [Certego S.R.L](https://certego.net?utm_source=intelowl).
- `FileScan_Upload_File`: Upload your file to extract IoCs from executable files, documents and scripts via [FileScan.io API](https://www.filescan.io/api/docs).
- `HashLookupServer_Get_File`: check if a md5 or sha1 is available in the database of [known file hosted by CIRCL](https://github.com/adulau/hashlookup-server)
- `HybridAnalysis_Get_File`: check file hash on [HybridAnalysis](https://www.hybrid-analysis.com/) sandbox reports
- `Intezer_Scan`: scan a file on [Intezer](https://analyze.intezer.com/?utm_source=IntelOwl). Register for a free community account [here](https://analyze.intezer.com/sign-in?utm_source=IntelOwl)
- `Malpedia_Scan`: scan a binary or a zip file (pwd:infected) against all the yara rules available in [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- `MalwareBazaar_Get_File`: Check if a particular malware sample is known to [MalwareBazaar](https://bazaar.abuse.ch/)
- `MISPFIRST_Check_Hash`: check a file hash on the FIRST MISP instance
- `MISP_Check_Hash`: check a file hash on a MISP instance
- `MWDB_Scan`: [mwdblib](https://mwdb.readthedocs.io/en/latest/) Retrieve malware file analysis from repository maintained by CERT Polska MWDB.
- `OTX_Check_Hash`: check file hash on [Alienvault OTX](https://otx.alienvault.com/)
- `SublimeSecurity`: Analyze an Email with [Sublime Security](https://docs.sublimesecurity.com/docs) live flow
- `Triage_Scan`: leverage [Triage](https://tria.ge) sandbox environment to scan various files
- `UnpacMe_EXE_Unpacker`: [UnpacMe](https://www.unpac.me/) is an automated malware unpacking service
- `Virushee_Upload_File`: Check file hash and upload file sample for analysis on [Virushee API](https://api.virushee.com/).
- `VirusTotal_v3_Get_File_And_Scan`: check file hash on VirusTotal. If not already available, send the sample and perform a scan
- `VirusTotal_v3_Get_File`: check only the file hash on VirusTotal (this analyzer is disabled by default to avoid multiple unwanted queries. You have to change that flag [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) to use it)
- `VirusTotal_v2_Get_File`: check file hash on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) to use it)
- `VirusTotal_v2_Scan_File`: scan a file on VirusTotal using old API endpoints (this analyzer is disabled by default. You have to change that flag [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) to use it)
- `YARAify_File_Scan`: scan a file against public and non-public YARA and ClamAV signatures in [YARAify](https://yaraify.abuse.ch/) public service
- `YARAify_File_Search`: scan an hash against [YARAify](https://yaraify.abuse.ch/) database

##### Observable analyzers (ip, domain, url, hash)

###### Internal tools

- `CheckDMARC`: An SPF and DMARC DNS records validator for domains.
- `DNStwist`: Scan a url/domain to find potentially malicious permutations via dns fuzzing. [dnstwist repo](https://github.com/elceef/dnstwist)
- `Thug_URL_Info`: Perform hybrid dynamic/static analysis on a URL using [Thug low-interaction honeyclient](https://thug-honeyclient.readthedocs.io/)

###### External services

* `AbuseIPDB`: check if an ip was reported on [AbuseIPDB](https://www.abuseipdb.com/)
* `Anomali_Threatstream_PassiveDNS`: Return information from passive dns of Anomali. On [Anomali Threatstream](https://www.anomali.com/products/threatstream) PassiveDNS Api. 
* `Auth0`: scan an IP against the Auth0 API
* `BinaryEdge`: Details about an Host. List of recent events for the specified host, including details of exposed ports and services using [IP query](https://docs.binaryedge.io/api-v2/#v2queryiptarget) and return list of subdomains known from the target domains using [domain query](https://docs.binaryedge.io/api-v2/#v2querydomainssubdomaintarget)
* `BitcoinAbuse` : Check a BTC address against bitcoinabuse.com, a public database of BTC addresses used by hackers and criminals.
* `Censys_Search`: scan an IP address against [Censys](https://censys.io/) View API
* `CheckPhish`: [CheckPhish](https://checkphish.ai/checkphish-api/) can detect phishing and fraudulent sites.
* `CIRCLPassiveDNS`: scan an observable against the CIRCL Passive DNS DB
* `CIRCLPassiveSSL`: scan an observable against the CIRCL Passive SSL DB
* `Classic_DNS`: Retrieve current domain resolution with default DNS
* `CloudFlare_DNS`: Retrieve current domain resolution with CloudFlare DoH (DNS over HTTPS)
* `CloudFlare_Malicious_Detector`: Leverages CloudFlare DoH to check if a domain is related to malware
* `Crowdsec`: check if an IP was reported on [Crowdsec](https://www.crowdsec.net/) Smoke Dataset
* `Cymru_Hash_Registry_Get_Observable`: Check if a particular hash is available in the malware hash registry of [Team Cymru](https://team-cymru.com/community-services/mhr/)
* `DNSDB`: scan an observable against the [Passive DNS Farsight Database](https://www.farsightsecurity.com/solutions/dnsdb/) (support both v1 and v2 versions)
* `DNS0_EU`: Retrieve current domain resolution with DNS0.eu DoH (DNS over HTTPS)
* `DNS0_EU_Malicious_Detector`: Check if a domain or an url is marked as malicious in DNS0.eu database ([Zero](https://www.dns0.eu/zero) service)
* `DocGuard_Get`: check if an hash was analyzed on DocGuard. [DocGuard](https://www.docguard.io)
* `FileScan_Search`: Finds reports and uploaded files by various tokens, like hash, filename, verdict, IOCs etc via [FileScan.io  API](https://www.filescan.io/api/docs).
* `FireHol_IPList`: check if an IP is in [FireHol's IPList](https://iplists.firehol.org/)
* `GoogleSafebrowsing`: Scan an observable against GoogleSafeBrowsing DB
* `GoogleWebRisk`: Scan an observable against WebRisk API (Commercial version of Google Safe Browsing). Check the [docs](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#analyzers-with-special-configuration) to enable this properly
* `Google_DNS`: Retrieve current domain resolution with Google DoH (DNS over HTTPS)
* `GreedyBear`: scan an IP or a domain against the [GreedyBear](https://greedybear.honeynet.org/) API (requires API key)
* `GreyNoise`: scan an IP against the [Greynoise](https://www.greynoise.io/) API (requires API key)
* `GreyNoiseCommunity`: scan an IP against the [Community Greynoise API](https://www.greynoise.io/) (requires API key))
* `HashLookupServer_Get_Observable`: check if a md5 or sha1 is available in the database of [known file hosted by CIRCL](https://github.com/adulau/hashlookup-server)
* `HoneyDB_Get`: [HoneyDB](https://honeydb.io/) IP lookup service
* `HoneyDB_Scan_Twitter`: scan an IP against HoneyDB.io's Twitter Threat Feed
* `Hunter_How`: Scans IP and domain against [Hunter_How API](https://hunter.how/search-api).
* `Hunter_Io`: Scans a domain name and returns set of data about the organisation, the email address found and additional information about the people owning those email addresses.
* `HybridAnalysis_Get_Observable`: search an observable in the [HybridAnalysis](https://www.hybrid-analysis.com/) sandbox reports
* `InQuest_DFI`: Deep File Inspection by [InQuest Labs](https://labs.inquest.net/dfi)
* `InQuest_IOCdb`: Indicators of Compromise Database by [InQuest Labs](https://labs.inquest.net/iocdb)
* `InQuest_REPdb`: Search in [InQuest Lab's](https://labs.inquest.net/repdb) Reputation Database
* `IPApi`: Get information about IPs using [batch-endpoint](https://ip-api.com/docs/api:batch) and DNS using [DNS-endpoint](https://ip-api.com/docs/dns).
* `IPInfo`: Location Information about an IP
* `Intezer_Get`: check if an analysis related to a hash is available in [Intezer](https://analyze.intezer.com/?utm_source=IntelOwl). Register for a free community account [here](https://analyze.intezer.com/sign-in).
* `Koodous`: [koodous API](https://docs.koodous.com/api/) get information about android malware.
* `MalwareBazaar_Get_Observable`: Check if a particular malware hash is known to [MalwareBazaar](https://bazaar.abuse.ch/)
* `MalwareBazaar_Google_Observable`: Check if a particular IP, domain or url is known to MalwareBazaar using google search
* `MaxMindGeoIP`: extract GeoIP info for an observable
* `MISP`: scan an observable on a MISP instance
* `MISPFIRST`: scan an observable on the FIRST MISP instance
* `Mnemonic_PassiveDNS` : Look up a domain or IP using the [Mnemonic PassiveDNS public API](https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview).
* `MWDB_Get`: [mwdblib](https://mwdb.readthedocs.io/en/latest/) Retrieve malware file analysis by hash from repository maintained by CERT Polska MWDB.
* `ONYPHE`: search an observable in [ONYPHE](https://www.onyphe.io/)
* `OpenCTI`: scan an observable on an [OpenCTI](https://github.com/OpenCTI-Platform/opencti) instance
* `OTXQuery`: scan an observable on [Alienvault OTX](https://otx.alienvault.com/)
* `Phishstats`: Search [PhishStats API](https://phishstats.info/) to determine if an IP/URL/domain is malicious.
* `Phishtank`: Search an url against [Phishtank](https://phishtank.org/api_info.php) API
* `Pulsedive`: Scan indicators and retrieve results from [Pulsedive's API](https://pulsedive.com/api/).
* `Quad9_DNS`: Retrieve current domain resolution with Quad9 DoH (DNS over HTTPS)
* `Quad9_Malicious_Detector`: Leverages Quad9 DoH to check if a domain is related to malware
* `Robtex`: scan a domain/IP against the Robtex Passive DNS DB
* `Securitytrails`: scan an IP/Domain against [Securitytrails](https://securitytrails.com/) API
* `Shodan_Honeyscore`: scan an IP against [Shodan](https://www.shodan.io/) Honeyscore API
* `Shodan_Search`: scan an IP against [Shodan](https://www.shodan.io/) Search API
* `Spyse`: Scan domains, IPs, emails and CVEs using Spyse's API. Register [here](https://spyse.com/user/registration).
* `SSAPINet`: get a screenshot of a web page using [screenshotapi.net](https://screenshotapi.net/) (external source); additional config options can be added to `extra_api_params` [in the config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json).
* `Stalkphish`: Search [Stalkphish API](https://www.stalkphish.io/) to retrieve information about a potential phishing site (IP/URL/domain/Generic).
* `Stratosphere_Blacklist`: Cross-reference an IP from blacklists maintained by [Stratosphere Labs](https://www.stratosphereips.org/attacker-ip-prioritization-blacklist)
* `TalosReputation`: check an IP reputation from [Talos](https://talosintelligence.com/reputation_center/)
* `ThreatFox`: search for an IOC in [ThreatFox](https://threatfox.abuse.ch/api/)'s database
* `Threatminer`: retrieve data from [Threatminer](https://www.threatminer.org/) API
* `TorProject`: check if an IP is a Tor Exit Node
* `Triage_Search`: Search for reports of observables or upload from URL on triage cloud
* `Tranco`: Check if a domain is in the latest [Tranco](https://tranco-list.eu/) ranking top sites list
* `URLhaus`: Query a domain or URL against [URLhaus](https://urlhaus.abuse.ch/) API.
* `UrlScan_Search`: Search an IP/domain/url/hash against [URLScan](https://urlscan.io) API
* `UrlScan_Submit_Result`: Submit & retrieve result of an URL against [URLScan](https://urlscan.io) API
* `Virushee_CheckHash`: Search for a previous analysis of a file by its hash (SHA256/SHA1/MD5) on [Virushee API](https://api.virushee.com/).
* `VirusTotal_v3_Get_Observable`: search an observable in the VirusTotal DB
* `Whoisxmlapi`: Fetch WHOIS record data, of a domain name, an IP address, or an email address.
* `WhoIs_RipeDB_Search` : Fetch whois record data of an IP address from Ripe DB using their [search API](https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-search) (no API key required)
* `XForceExchange`: scan an observable on [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
* `YARAify_Search`: lookup a file hash in [Abuse.ch YARAify](https://yaraify.abuse.ch/)
* `YETI` (Your Everyday Threat Intelligence): scan an observable on a [YETI](https://github.com/yeti-platform/yeti) instance.
* `Zoomeye`: [Zoomeye](https://www.zoomeye.org) Cyberspace Search Engine recording information of devices, websites, services and components etc..

##### Generic analyzers (email, phone number, etc.; anything really)

Some analyzers require details other than just IP, URL, Domain, etc. We classified them as `generic` Analyzers. Since the type of field is not known, there is a format for strings to be followed.

###### Internal tools

- `CyberChef`: Run a query on a [CyberChef server](https://github.com/gchq/CyberChef-server) using pre-defined or custom recipes.

###### External services
* `Anomali_Threatstream_Confidence`: Give max, average and minimum confidence of maliciousness for an observable. On [Anomali Threatstream](https://www.anomali.com/products/threatstream) Confidence API.
* `Anomali_Threatstream_Intelligence`: Search for threat intelligence information about an observable. On [Anomali Threatstream](https://www.anomali.com/products/threatstream) Intelligence API.
* `CRXcavator`: scans a chrome extension against crxcavator.io
* `CryptoScamDB_CheckAPI`: Scan a cryptocurrency address, IP address, domain or ENS name against the [CryptoScamDB](https://cryptoscamdb.org/) API.
* `Darksearch_Query`: Search a keyword against darksearch.io's search API. It's possible to make complex queries using boolean logic. For example, `OSINT AND CTI OR intelowl NOT hack` is a valid observable name.
* `Dehashed_Search`: Query any observable/keyword against https://dehashed.com's search API.
* `EmailRep`: search an email address on [emailrep.io](https://emailrep.io)
* `HaveIBeenPwned`: [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) checks if an email address has been involved in a data breach
* `IntelX_Intelligent_Search`: [IntelligenceX](https://intelx.io/) is a search engine and data archive. Fetches emails, urls, domains associated with an observable or a generic string.
* `IntelX_Phonebook`: [IntelligenceX](https://intelx.io/) is a search engine and data archive. Fetches emails, urls, domains associated with an observable or a generic string.
* `MISP`: scan an observable on a MISP instance
* `VirusTotal_v3_Intelligence_Search`: Perform advanced queries with [VirusTotal Intelligence](https://developers.virustotal.com/reference/intelligence-search) (requires paid plan)
* `WiGLE`: Maps and database of 802.11 wireless networks, with statistics, submitted by wardrivers, netstumblers, and net huggers.
* `YARAify_Generics`: lookup a YARA rule (default), ClamAV rule, imphash, TLSH, telfhash or icon_dash in [YARAify](https://yaraify.abuse.ch/)

##### Optional analyzers

[Some analyzers are optional](Advanced-Usage.html#optional-analyzers) and need to be enabled explicitly.

#### Analyzers Customization

You can create new analyzers based on already existing modules by changing the configuration values inside `configuration/analyzer_config.json`. This file is mounted as a docker volume, so you won't need to rebuild the image.

You may want to change this configuration to add new analyzers or to change the configuration of some of them. The name of the analyzers can be changed at every moment based on your wishes.

The following are all the keys that you can change without touching the source code:
- `name`: Name of the analyzer
- `description`: Description of the analyzer
- `python_module`: Python path of the class that will be executed 
- `disabled`: you can choose to disable certain analyzers, then they won't appear in the dropdown list and won't run if requested.
- `leaks_info`: if set, in the case you specify via the API that a resource is sensitive, the specific analyzer won't be executed
- `external_service`: if set, in the case you specify via the API to exclude external services, the specific analyzer won't be executed
- `supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a different mimetype from the ones you specified, it won't be executed
- `not_supported_filetypes`: can be populated as a list. If set, if you ask to analyze a file with a mimetype from the ones you specified, it won't be executed
- `observable_supported`: can be populated as a list. If set, if you ask to analyze an observable that is not in this list, it won't be executed. Valid values are: `ip`, `domain`, `url`, `hash`, `generic`.
- `config`:
  - `soft_time_limit`: this is the maximum time (in seconds) of execution for an analyzer. Once reached, the task will be killed (or managed in the code by a custom Exception). Default `300`.
  - `queue`: this takes effects only when [multi-queue](Advanced-Configuration.html#multi-queue) is enabled. Choose which celery worker would execute the task: `local` (ideal for tasks that leverage local applications like Yara), `long` (ideal for long tasks) or `default` (ideal for simple webAPI-based analyzers).
Sometimes, it may happen that you would like to create a new analyzer very similar to an already existing one. Maybe you would like to just change the description and the default parameters.
A helpful way to do that without having to copy/pasting the entire configuration, is to click on the analyzer that you want to copy, make the desired changes, and click the `save as new` button.

<div class="admonition hint">
<p class="admonition-title">Hint: Advanced Configuration</p>
You can also modify analyzer specific parameters directly from the GUI. See <a href="./Advanced-Usage.html#customize-analyzer-execution">Customize analyzer execution at time of request</a>
</div>

### Connectors

Connectors are designed to run after every successful analysis which makes them suitable for automated threat-sharing. They support integration with other SIEM/SOAR projects, specifically aimed at Threat Sharing Platforms.

#### Connectors list

The following is the list of the available connectors. You can also navigate the same list via the

- Graphical Interface: once your application is up and running, go to the "Plugins" section
- [pyintelowl](https://github.com/intelowlproject/pyintelowl): `$ pyintelowl get-connector-config`

##### List of pre-built Connectors

- `MISP`: automatically creates an event on your MISP instance, linking the successful analysis on IntelOwl.
- `OpenCTI`: automatically creates an observable and a linked report on your OpenCTI instance, linking the the successful analysis on IntelOwl.
- `YETI`: YETI = Your Everyday Threat Intelligence. find or create observable on YETI, linking the successful analysis on IntelOwl.

#### Connectors customization

Connectors being optional are `enabled` by default.
You can disable them or create new connectors based on already existing modules by changing the configuration values inside the Django Admin interface at: `/admin/connectors_manager/connectorreport/`.


The following are all the keys that you can change without touching the source code:
 
- `name`: _same as analyzers_
- `description`: _same as analyzers_
- `python_module`: _same as analyzers_ 
- `disabled`: _same as analyzers_
- `config`:
  - `queue`: _same as analyzers_
  - `soft_time_limit`: _same as analyzers_

- `maximum_tlp` (default `CLEAR`, choices `CLEAR`, `GREEN`, `AMBER`, `RED`): specify the maximum TLP of the analysis up to which the connector is allowed to run. (e.g. if `maximum_tlp` is `GREEN`, it would run for analysis with TLPs `WHITE` and `GREEN`). To learn more about TLPs see [TLP Support](./Usage.md#tlp-support).
- `run_on_failure` (default: `true`): if they can be run even if the job has status `reported_with_fails` 

<div class="admonition warning">
<p class="admonition-title">Warning</p>
Changing other keys can break a connector. In that case, you should think about duplicating the configuration entry or python module with your changes.
</div>

### Managing Analyzers and Connectors

All plugins i.e. analyzers and connectors have `kill` and `retry` actions. In addition to that, all docker-based analyzers and connectors have a `healthcheck` action to check if their associated instances are up or not.

- **kill:**

  To stop a plugin whose status is `running`/`pending`:

  - GUI: Buttons on reports table on job result page.
  - PyIntelOwl: `IntelOwl.kill_analyzer` and `IntelOwl.kill_connector` function.
  - CLI: `$ pyintelowl jobs kill-analyzer <job_id> <analyzer_name>` and `$ pyintelowl jobs kill-connector <job_id> <connector_name>`
  - API: `PATCH /api/job/{job_id}/analyzer/{analyzer_name}/kill` and `PATCH /api/job/{job_id}/connector/{connector_name}/kill`

- **retry:**

  To retry a plugin whose status is `failed`/`killed`:

  - GUI: Buttons on reports table on job result page.
  - PyIntelOwl: `IntelOwl.retry_analyzer` and `IntelOwl.retry_connector` function,
  - CLI: `$ pyintelowl jobs retry-analyzer <job_id> <analyzer_name>` and `$ pyintelowl jobs retry-connector <job_id> <connector_name>`
  - API: `PATCH /api/job/{job_id}/analyzer/{analyzer_name}/retry` and `PATCH /api/job/{job_id}/connector/{connector_name}/retry`

- **healthcheck:**

  To check if docker container or external platform associated with an analyzer or connector respectively are up or not:

  - GUI: Buttons on analyzers table and connectors table.
  - PyIntelOwl: `IntelOwl.analyzer_healthcheck` and `IntelOwl.connector_healthcheck` methods.
  - CLI: `$ pyintelowl analyzer-healthcheck <analyzer_name>` and `$ pyintelowl connector-healthcheck <connector_name>`
  - API: `GET /api/analyzer/{analyzer_name}/healthcheck` and `GET /api /connector/{connector_name}/healthcheck`

### Visualizers

Visualizers are designed to run after the analyzers and the connectors.
The visualizer adds logic after the computations, allowing to show the final result in a different way than merely the list of reports.

Each visualizer must define a set of analyzers and connectors as requirement:
in fact the visualizers can not be chosen at the time of Job creation (once you click into the `Scan` button) but every single visualizer that it is configured and that has its requirements satisfied will be automatically selected and executed.

##### List of pre-built Visualizers

- `DNS`: displays the aggregation of every DNS analyzer report
- `Yara`: displays the aggregation of every matched rule by the `Yara` Analyzer


#### Visualizers customization
You can either disable or create new visualizers based on already existing modules by changing the configuration values inside the Django Admin interface: `/admin/visualizers_manager/visualizerreport/`.

The following are all the keys that you can change without touching the source code:
 
- `name`: _same as analyzers_
- `description`: _same as analyzers_
- `python_module`: _same as analyzers_ 
- `disabled`: _same as analyzers_
- `config`:
  - `queue`: _same as analyzers_
  - `soft_time_limit`: _same as analyzers_
- `analyzers`: List of analyzers that must be executed
- `connectors`: List of connectors that must be executed

### Playbooks

Playbooks are designed to be easy to share sequence of running Analyzers/Connectors on a particular kind of observable.

If you want to avoid to re-select/re-configure a particular combination of analyzers and connectors together every time, you should create a playbook out of it and use it instead. This is time saver.

This is a feature introduced since IntelOwl v4.1.0! Please provide feedback about it!

#### Playbooks List

The following is the list of the available pre-built playbooks. You can also navigate the same list via the

- Graphical Interface: once your application is up and running, go to the "Plugins" section
- [pyintelowl](https://github.com/intelowlproject/pyintelowl): `$ pyintelowl get-playbook-config`

##### List of pre-built playbooks

- `FREE_TO_USE_ANALYZERS`: A playbook containing all free to use analyzers.
- `Sample Static Anlysis`: A playbook containing all analyzers that perform static analysis on files.

#### Playbooks customization

You can create new playbooks via the Django Admin interface at `/admin/playbooks_manager/playbookconfig/`

The following are all the keys that you can leverage/change without touching the source code:

- `analyzers`: list of analyzers to execute
- `connectors`: list of connectors to execute
- `disabled`: _similar to analyzers_
- `description`: _similar to analyzers_
- `type`: list of observable types or files supported
- `runtime_configuration`: runtime configuration for each type of plugin

Another chance to create a new playbook is to leverage the "Save as Playbook" button that you can find on the top right of the Job Result Page.
In this way, after you have done an analysis, you can save the configuration of analyzers/connectors for re-use with a single click.

Those are the only ways to do that for now. We are planning to provide more easier ways to add new playbooks in the future.

---

To contribute to the project, see [Contribute](./Contribute.md).
