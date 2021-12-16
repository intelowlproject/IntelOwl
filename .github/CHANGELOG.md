# Changelog

[**Upgrade Guide**](https://intelowl.readthedocs.io/en/latest/Installation.html#update-to-the-most-recent-version)

## [v3.2.3](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.2.3)

**New Analyzers:**

- `Mnemonic_PassiveDNS`: Look up a domain or IP using the [Mnemonic PassiveDNS public API](https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview).
- `FileScan_Search`: Finds reports and uploaded files by various tokens, like hash, filename, verdict, IOCs etc via [FileScan.io API](https://www.filescan.io/api/docs)
- `FileScan_Upload_File`: Upload your file to extract IoCs from executable files, documents and scripts via [FileScan.io API](https://www.filescan.io/api/docs)
- `Yara_Scan_ATM_MALWARE`: analyze your files with the rules from this [repo](https://github.com/fboldewin/YARA-rules)

**Fixes & Improvements:**

- `HashLookupServer_*` analyzers now correctly support sha256 hashes
- added IP addresses support to `URLhaus` analyzer
- fixed `VirusTotal` analyzers to reduce quota consumption
- fixed `Dragonfly_Emulation` and `Quark_Engine_APK` analyzer
- updated `dnstwist`, `XLMMacroDeobfuscator` and other dependencies upgrades
- adjustments in the PR template

**For IntelOwl Contributors**

We updated the documentation on how to [Contribute](https://intelowl.readthedocs.io/en/latest/Contribute.html#rules). Please read through them if interested in contributing in the project.

## [v3.2.2](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.2.2)

**Notes:**

- The `Dragonfly_Emulation` analyzer will not work without this update.

**New Analyzers:**

- `BitcoinAbuse`: Check a BTC address against bitcoinabuse.com, a public database of BTC addresses used by hackers and criminals.
- `Phishstats`: Search [PhishStats](https://phishstats.info) API to determine if an IP/URL/domain/generic is malicious.
- `WhoIs_RipeDB_Search`: Fetch whois record data of an IP address from Ripe DB using their [search API](https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-search).

**Fixes & Improvements:**

- Bump `pydragonfly` dependency for `Dragonfly_Emulation` analyzer.
- Fixes in cloudfare based analyzers.
- Populate `not_supported_filetypes` field in `HashLookupServer_Get_File` analyzer.
- Use `force_unique_key` parameter in all docker based analyzers to prevent trivial errors.

## [v3.2.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.2.1)

> Update PyIntelOwl to version [4.1.3](https://github.com/intelowlproject/pyintelowl/blob/master/.github/CHANGELOG.md#413).

**REST API changes**:

- New parameter `minutes_ago` in the `/api/ask_analysis_availability` endpoint.

**Bug Fixes:**

- Fix AWS S3 storage not working for file analysis.
- Fix in intezer analyzers to correctly manage HashDoesNotExistError error
- Fix in `Fortiguard` analyzer.
- Temporary disable `Quark_Engine_APK` analyzer in CI tests because of [quark-engine/quark-engine#286](https://github.com/quark-engine/quark-engine/issues/286).

**Other:**

- Updated to python 3.9 in CI.
- Uniform docker-compose version in all docker-compose files.
- Use isort to sort import statements.

## [v3.2.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.2.0)

**New Analyzers:**

- `CryptoScamDB_CheckAPI`: Scan a cryptocurrency address, IP address, domain or ENS name against the [CryptoScamDB](https://cryptoscamdb.org/) API.
- `Dragonfly_Emulation`: Emulate and analyze malware in a customizable manner with [Dragonfly](https://dragonfly.certego.net/?utm_source=intelowl) sandbox.
  > Dragonfly is a new public service by [Certego](https://certego.net?utm_source=intelowl) developed by the same team behind IntelOwl. [Sign up](https://dragonfly.certego.net/register?utm_source=intelowl) today on Dragonfly for free access!

**Bug Fixes:**

- Fixed [743](https://github.com/intelowlproject/IntelOwl/issues/743): File mime_type identification error. Thanks to @OG-Sadpanda for the report.

**Other:**

- Extended docker bind mount to all configuration files
- Added new `test.flower.override.yml` and `test.multi-queue.override.yml` docker-compose files for flower and multi_queue options in test (local) mode.
- Bump docker-compose file versions to 3.8
- Bump some python dependencies

## [v3.1.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.1.0)

> 🎉 We are glad to welcome [Tines](https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=intelowl) as a new sponsor for IntelOwl. Read everything about this partnership [in the Tines' blog](https://www.tines.com/blog/announcing-our-sponsorship-of-intel-owl).

**Notes:**

- Update PyIntelOwl to version [4.1.0](https://github.com/intelowlproject/pyintelowl/blob/master/.github/CHANGELOG.md#410).
- Introducing IntelOwl Official [Parternship & Sponsorship Tiers](https://github.com/intelowlproject/IntelOwl/blob/master/.github/partnership_and_sponsors.md).
- IntelOwl now has an official integration in [Tines](https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=intelowl) templates.

**REST API changes:**

- `/api/analyze_file` and `/api/analyze_observable`:
  - Request Body:
    - deprecate `md5` attribute. Will now be calculated on server.
    - deprecate `tags_id` attribute in favor of `tags_labels`. Previously, the `tags_id` attribute would accept a list of tag indices, now the `tags_labels` accepts a list of tag labels (non-existing `Tag` objects are created automatically with a randomly generated color).
    - `observable_classification` attribute is now optional. If not passed, the application tries to guess the correct classification using regular expressions.
  - Response Body: now also returns a `connectors_running` attribute that is a list of connectors executed for the specific job.

**Misc:**

- Added default parameters to `entrypoint_flower.sh` to allow retrocompatibility.
- Fixes in documentation.
- Bump some dependencies.

## [v3.0.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.0.1)

This is a minor patch release.

- Bug Fix: Add `required` boolean attribute to `secrets` dict of configuration files. (Issue [#702](https://github.com/intelowlproject/IntelOwl/issues/702)).
- Bug Fix: Some fixes and adjusts in documentation.
- Analyzer adjusts: DNSdb, cuckoo, maxmind, greynoise analyzers.
- Deps: Bump some requirements.

## [v3.0.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.0.0)

> Note: This is a major release with MANY breaking changes.
>
> ✒️ [Link](https://www.honeynet.org/2021/09/13/intel-owl-release-v3-0-0/) to the blogpost announcing the release and summary of top new features.
>
> 💻 GUI changes can be seen in action on the [demo](https://intelowlclient.firebaseapp.com/pages/connectors).

**Notes:**

- Update PyIntelOwl to version [4.0.0](https://github.com/intelowlproject/pyintelowl/blob/master/.github/CHANGELOG.md#400).
- If you modified your local `analyzer_config.json` file, then you will need to merge the changes manually because of the new format.

**Features:**

- Plugins (analyzers/connectors) that are not properly configured will not run even if requested. They will be marked as disabled from the dropdown on the analysis form and as a bonus you can also see if and why a plugin is not configured on the GUI tables.
- Added `kill`, `retry` and `healthcheck` features to analyzers and connectors. See [Managing Analyzers and Connectors](https://intelowl.readthedocs.io/en/master/Usage.html#managing-analyzers-and-connectors).
- Standardized threat-sharing using Traffic Light Protocol or `TLP`, thereby deprecating the use of booleans `force_privacy`, `disable_external_analyzers` and `private`. See [TLP Support](https://intelowl.readthedocs.io/en/master/Usage.html#tlp-support). This makes the analysis form much more easier to use than before.

**New class of plugins called _Connectors_:**

- Connectors are designed to run after every successful analysis which makes them suitable for automated threat-sharing. Built to support integration with other SIEM/SOAR projects specifically aimed at Threat Sharing Platforms. See [Available Connectors](https://intelowl.readthedocs.io/en/master/Usage.html#available-connectors).
- Newly added connectors for threat-sharing:
  - `MISP`: automatically creates an event on your MISP instance.
  - `OpenCTI`: automatically creates an observable and a linked report on your OpenCTI instance.
  - `YETI`: find/create an observable on YETI.
- New `connectors_config.json` file for storing connectors related configuration.

**New analyzers configuration format:**

- The `additional_config_params` attribute was split into the following 3 individual attributes.
  - `config`: Includes common parameters - `queue` and `soft_time_limit`.
  - `params`: Includes default value, datatype and description for each [Analyzer](https://intelowl.readthedocs.io/en/master/Usage.html#analyzers-customization) or [Connector](https://intelowl.readthedocs.io/en/master/Usage.html#connectors-customization) specific parameters that modify runtime behaviour.
  - `secrets`: Includes analyzer or connector specific secrets (e.g. API Key) name along with the secret's description. All secrets are required.

**New inbuilt analyzers/fixes to existing:**

- New `Spyse` analyzer: Scan domains, IPs, emails and CVEs using Spyse's API. Register [here](https://spyse.com/user/registration).
- New `OpenCTI` analyzer: scan an observable on an OpenCTI instance.
- New `Intezer_Get` analyzer: check Managing Analyzers and Connectors if an analysis related to a hash is available in [Intezer](https://analyze.intezer.com/?utm_source=IntelOwl)
- New `MWDB_Get` analyzer: [mwdblib](https://mwdb.readthedocs.io/en/latest/) Retrieve malware file analysis by hash from repository maintained by CERT Polska MWDB.
- New `YETI` analyzer (YETI = Your Everyday Threat Intelligence): scan an observable on a YETI instance.
- New `HashLookupServer_Get_Observable` and `HashLookupServer_Get_File` analyzers: check if a md5 or sha1 is available in the database of [known file hosted by CIRCL](https://github.com/adulau/hashlookup-server)
- New `ClamAV` analyzer: scan files for viruses/malwares/trojans using [ClamAV antivirus engine](https://docs.clamav.net/).
- Fixed `Tranco` Analyzer pointing to the wrong `python_module`
- Removed `CirclePDNS` default value in `env_file_app_template`
- VirusTotal v3: New configuration options: `include_behaviour_summary` for behavioral analysis and `include_sigma_analyses` for sigma analysis report of the file. See [Customize Analyzers](https://intelowl.readthedocs.io/en/master/Advanced-Usage.html#customize-analyzer-execution-at-time-of-request).

**REST API changes:**

- The `/api/send_analysis_request` endpoint was split into two individual endpoints, namely, `/api/analyze_file` and `/api/analyze_observable` to allow for various improvements.
- Updated endpoint for downloading job sample: `/api/jobs/{id}/download_sample`
- Updated `/api/ask_analysis_availability` to be a `POST` endpoint to allow for various improvements.

**Misc:**

- Updated the elasticsearch mapping for `Job` model along with updated [Saved Object](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/Kibana-Saved-Conf.ndjson) for Kibana.

## [v2.5.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.5.0)

**New Inbuilt Analyzers:**

- New `Dehashed_Search` analyzer: Query any observable/keyword against Dehashed's search API (https://dehashed.com).

**Analyzer Improvements & Fixes:**

- Improvements in the `cuckoo_scan.py`, `file_info.py`, `abuseipdb.py`, and `otx.py`.
- Fix: Exiftool download link was broken (Issue [#507](https://github.com/intelowlproject/IntelOwl/issues/507))

**Other:**

- as always: fixes, tweaks and dependencies upgrades.

**Important Notes:**

- This is the last stable release in the v2.x pipeline. The next release of IntelOwl, v3.0, will bring exciting new features and breaking changes. Some things that we have in the works:
  - A new class of plugins called _Connectors_ to allow integration with other SIEM/SOAR projects specifically aimed at Threat Sharing Platforms.
  - Support for MISP and Open-CTI.
  - automatically disabling of unconfigured analyzers
  - ...and much more
- IntelOwl joined the official [Docker Open Source Program](https://www.docker.com/blog/expanded-support-for-open-source-software-projects/). :tada:

## [v2.4.2](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.4.2)

- darksearch.io search API analyzer
- improved abuseipdb analyzer to show matched categories in a human readable form too
- improved HoneyDB analyzer
- as always: fixes, tweaks and dependencies upgrades.

## [v2.4.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.4.1)

A lot of different fixes, tweaks and dependencies upgrades. Also the documentation was updated

## [v2.4.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.4.0)

We welcome new GSoC students ([Sarthak Khattar](https://twitter.com/Mr_Momo07) and [Shubham Pandey](https://twitter.com/imshubham31)) in the Organization!

Main updates:

- new release of the official GUI [IntelOwl-Ng](https://github.com/intelowlproject/IntelOwl-ng/releases/tag/v2.1.0)
- added [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) analyzer

Then a lot of maintenance and overall project stability issues solved:

- removed `eventlet` broken dependency
- bumped new versions of a lot of dependencies
- Improved "Installation" and "Contribute" documentation
- added new badges to the README
- added `--django-server` [option](https://intelowl.readthedocs.io/en/latest/Contribute.html#how-to-start) to speed up development
- analyzed files are now correctly deleted with the periodic cronjob
- other little refactors and fixes

## [v2.3.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.3.0)

- Added [API documentation](https://intelowl.readthedocs.io) with both [Redoc](https://github.com/Redocly/redoc) and [OpenAPI](https://github.com/OAI/OpenAPI-Specification) Format

**NEW INBUILT ANALYZERS:**

- added [ThreatFox Abuse.ch](https://threatfox.abuse.ch) analyzer for observables
- added [GreyNoise Community](https://developer.greynoise.io/reference/community-api) analyzer for IP addresses
- added [FireHol](http://iplists.firehol.org/) analyzer to detect malicious IP addresses
- added [SSAPINet](https://screenshotapi.net) analyzer to capture a screenshot of a web page
- added optional [Google Rendertron](https://github.com/GoogleChrome/rendertron) analyzer to capture a screenshot of a web page without using an external source (this won't leak the URL externally like the previous one)
- added [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) analyzer for observables
- added [Google Web Risk](https://cloud.google.com/web-risk) analyzer, an alternative of GoogleSafeBrowsing for commercial purposes

**Others:**

- A lot of dependency upgrades and clean up of unnecessary ones
- refactor to some APIs + added tests for untested APIs
- adjustments to MISP, OTX and Cymru analyzers

## [v2.2.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.2.0)

- IntelOwl has **brand new project logos**. Thanks to @Certego.

**New Features:**

- Introduced the possibility to enable/disable SSL check while connecting to a MISP platform. Thanks to @raw-data.
- Users can now request to kill a job whose status is `running`.
  - GUI: Button on job result page.
  - PyIntelOwl: `IntelOwl.kill_running_job` function
  - CLI: `$ pyintelowl jobs kill <id>`
  - API: `PATCH /api/jobs/{id}/kill`
- Users can now delete a job.
  - GUI: Button on job result page.
  - PyIntelOwl: `IntelOwl.delete_job_by_id` function
  - CLI: `$ pyintelowl jobs rm <id>`
  - API: `DELETE /api/jobs/{id}`
- Users can now delete a tag from the command line/pyintelowl (Eg: `$ pyintelowl tags rm <id>`). (Before, it was only possible from the web GUI or direct HTTP call.)

**Others:**

- Deprecate `ask_analysis_result` API.
- Update permission section of docs

## [v2.1.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.1.1)

**FIXES/IMPROVEMENTS/Dependency upgrades**

- now `start.py` works with the most recent 1.28.2 version of docker-compose
- updated Django, Yara and Speakeasy to most recent versions

## [v2.1.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.1.0)

**IMPORTANT FIX**
We changed `docker-compose` file names for optional analyzers. In the `v.2.0.0` this broke Docker Hub builds, causing them to fail. Please upgrade to this version to be able to use the optional analyzers again.

**NEW INBUILT ANALYZERS:**

- added [CRXCavator](https://crxcavator.io/) analyzer for malicious Chrome extensions
- added [CERT Polska MWDB](https://mwdb.cert.pl) analyzer for malicious files

**FIXES/IMPROVEMENTS/Dependency upgrades:**

- updated `Quark_Engine` to last version and fixed rules
- `Maxmind` analyzer now retrieves City data too
- fixes for `Qiling` analyzer
- re-enabled `APKiD_Scan_APK_DEX_JAR` analyzer for Android samples
- adjusts to auto-build, PR template and documentation

## [v2.0.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v2.0.0)

**BREAKING CHANGES:**

- moved docker and docker-compose files under `docker/` folder.
- users upgrading from previous versions need to manually move `env_file_app`, `env_file_postgres` and `env_file_integrations` files under `docker/`.
- users are to use the new [start.py](https://intelowl.readthedocs.io/en/stable/Installation.html#run) method to build or start IntelOwl containers
- moved the following analyzers together in a specific optional docker container named `static_analyzers`.
  - [`Capa`](https://github.com/fireeye/capa)
  - [`PeFrame`](https://github.com/guelfoweb/peframe)
  - `Strings_Info_Classic` (based on [flarestrings](https://github.com/fireeye/stringsifter))
  - `Strings_Info_ML` (based on [stringsifter](https://github.com/fireeye/stringsifter))

Please see [docs](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#optional-analyzers) to understand how to enable these optional analyzers

**NEW INBUILT ANALYZERS:**

- added [Qiling](https://github.com/qilingframework/qiling) file analyzer. This is an optional analyzer (see [docs](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#optional-analyzers) to understand how to activate it).
- added [Stratosphere blacklists](https://www.stratosphereips.org/attacker-ip-prioritization-blacklist) analyzer
- added [FireEye Red Team Tool Countermeasures](https://github.com/fireeye/red_team_tool_countermeasures) Yara rules analyzer
- added [emailrep.io](https://emailrep.io/) analyzer
- added [Triage](https://tria.ge) analyzer for observables (`search` API)
- added [InQuest](https://labs.inquest.net) analyzer
- added [WiGLE](api.wigle.net) analyzer
- new analyzers were added to the `static_analyzers` optional docker container (see [docs](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#optional-analyzers) to understand how to activate it).
  - [`FireEye Floss`](https://github.com/fireeye/flare-floss) strings analysis.
  - [`Manalyze`](https://github.com/JusticeRage/Manalyze) file analyzer

**FIXES/IMPROVEMENTS/Dependency upgrades:**

- upgraded main Dockerfile to python 3.8
- added support for the `generic` observable type. In this way it is possible to build analyzers that can analyze everything and not only IPs, domains, URLs or hashes
- added [Multi-queue](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#multi-queue) option to optimize usage of Celery queues. This is intended for advanced users.
- updated GUI to new [IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng/releases/tag/v1.7.0) version
- upgraded [Speakeasy](https://github.com/fireeye/speakeasy), [Quark-Engine](https://github.com/quark-engine/quark-engine) and [Dnstwist](https://github.com/elceef/dnstwist) analyzers to last versions
- moved from Travis CI to Github CI
- added [CodeCov](https://about.codecov.io/) coverage support (_so we will be improving the test coverage shortly_)
- moved PEFile library pointer to a forked [pip repo](https://pypi.org/project/pefile-fork/) that contains some fixes.
- fix to log directiories that could result in some optional analyzers to break
- added milliseconds to logs

## [v1.9.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.9.1)

This version was released earlier to fix installation problems triggered by the new version of `pip` (`peepdf`package was incompatible and had to be changed).

**NEW INBUILT ANALYZERS:**

- Added **MalwareBazaar_Google_Observable** analyzer: Check if a particular IP, domain or url is known to [MalwareBazaar](https://bazaar.abuse.ch) using google search
- Added [InQuest YARA rules](https://github.com/InQuest/yara-rules) analyzer.
- Added [StrangerealIntel Daily Ioc Yara rules](https://github.com/StrangerealIntel/DailyIOC) analyzer.

**FIXES/IMPROVEMENTS/Dependency upgrades:**

- changed `peepdf` pip repo to `peepdf-fork` to fix broken installation
- adjustments to documentation
- upgraded `quark-engine` to v20.11
- fixes to `UnpacMe_EXE_Unpacker` and `PE_Info` analyzers
- managed RAM utilization by celery to avoid issues when using IntelOwl for a lot of analysis.
- added PR template
- removed nginx banner

## [v1.9.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.9.0)

**NEW INBUILT ANALYZERS:**

- Added [Triage](https://tria.ge) file analyzer.
- Added [Zoomeye](https://www.zoomeye.org) analyzer.
- Added [Dnstwist](https://github.com/elceef/dnstwist) analyzers.
- Added [Ipinfo](https://ipinfo.io) analyzer.
- Added [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) analyzer.
- Added [Samir YARA rules](https://github.com/sbousseaden/YaraHunts) analyzer.

**FIXES/IMPROVEMENTS/Dependency upgrades:**

- several little fixes on some analyzers (`OTXQuery`, `DNSDB`, `Classic_DNS`, `Fortiguard`, `XLMDeobfuscator`)
- increased filename `max_length` to `512`
- added validation checks to avoid DB problems
- upgraded Yara to v4.0.2
- added Yara rule location to the analyzer output

## [v1.8.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.8.0)

**BREAKING CHANGE:**

- New Token authentication method using the django-rest-durin package. When upgrading IntelOwl to `v1.8.0`, pyintelowl users must upgrade it too to `v2.0.0`. Also, pyintelowl users must create a new valid Token to interact with IntelOwl. More details, [here](https://github.com/intelowlproject/pyintelowl#generate-api-key).
- Many analyzer variants for VirusTotal and Thug have been removed from `analyzer_config.json` file.
  Explanation at [#224](https://github.com/intelowlproject/IntelOwl/issues/224). With added docs on how to use custom analyzer configuration at runtime.
- Other analyzers were renamed due to better clarity and format:
  - `ActiveDNS_Classic` -> `Classic_DNS`
  - `ActiveDNS_CloudFlare` -> `CloudFlare_DNS`
  - `ActiveDNS_CloudFlare_Malware` -> `CloudFlare_Malicious_Detector`
  - `ActiveDNS_Google` -> `Google_DNS`

**NEW INBUILT ANALYZERS:**

- Added [URLScan](https://urlscan.io/about-api) analyzer.
- Added [Quad9](https://www.quad9.net/) analyzers (DNS + Malicious_Detector).
- Added [Phishtank](http://phishtank.org/) analyzer.
- Added [Stratosphere YARA rules](https://github.com/stratosphereips/yara-rules) analyzer.
- Upgraded Speakeasy to 1.4.7.
- Added extra options to DNSDB analyzer + support for API v2.
- Added [PDFid](https://github.com/mlodic/pdfid) analysis to `PDF_Info` analyzer.

**FIXES/IMPROVEMENTS/Dependency upgrades:**

- Changed Oletools pointer to main repository version (0.56).
- Changed docs style to use the `Sphinx` theme.
- Fix for issue [#138](https://github.com/intelowlproject/IntelOwl/issues/138).
- Update Django and Django-Rest-Framework versions.
- Updates to recent versions of postgres, nginx and rabbit-mq docker images.
- Loads of internal changes and code optimizations.
- Added more info in contributing section of docs.

## [v1.7.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.7.1)

Improvements to recent malicious document analysis:

- Added [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) analyzer, refer #196 thanks to @0ssigeno
- Updated oletools to last available changes

Other:

- updated black to 20.8b1 and little fix in the docs

## [v1.7.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.7.0)

- 3 new analyzers which can be used out of the box:
  - `UnpacMe_EXE_Unpacker`: [UnpacMe](https://www.unpac.me/) is an automated malware unpacking service. (Thanks to @0ssigeno)
  - `CheckDMARC`: [checdmarc](https://github.com/domainaware/checkdmarc) provides SPF and DMARC DNS records validator for domains. (Thanks to @goodlandsecurity)
  - `Whoisxmlapi`: Fetch WHOIS record data, of a domain name, an IP address, or an email address. (Thanks to @tamthaitu)
- Some fixes to Cymru Malware and VT2 analyzers.
- Now you or your organization can get paid support/extra features/custom integrations for IntelOwl via xscode platform. [Details](https://xscode.com/intelowlproject/IntelOwl).

## [v1.6.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.1)

This patch allows to download the most recent docker image of IntelOwl. Previous version was downloading the old (`v1.5.1`) docker image.

Please see [v1.6.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.0) for release details.

## [v1.6.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.0)

- added new analyzer for [FireEye speakeasy](https://github.com/fireeye/speakeasy)
- updated [FireEye Capa](https://github.com/fireeye/capa) to 1.1.0
- updated docs, including instructions for [Remnux](https://docs.remnux.org) users and a new ["How to use pyintelowl" video](https://www.youtube.com/watch?v=fpd6Kt9EZdI).

## [v1.5.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.5.1)

Patch after **v1.5.0**.

- Fixed `runtime_configuration` JSON serialization bug when requesting file scan.

## [v1.5.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.5.0)

> This release contains a bug that was fixed in v1.5.1. We recommend cloning the `master` branch.

**Features:**

- Ability to pass a JSON field `runtime_configuration` for dynamic configuration per scan request. [Demo GIF](https://imgur.com/5sxp9JP).
- IntelligenceX's phonebook API for observables.
- Increased JWT token lifetime for webapp. ([Ref.](https://github.com/intelowlproject/IntelOwl/issues/163#issuecomment-678223186)).

**Breaking Changes:**

- Moved `ldap_config.py` under `configuration/` directory. If you were using LDAP before this release, please refer the [updated docs](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#ldap).

**Fixes:**

- Updates and fixes to: `Doc_info`, `PE_Info`, `VirusTotal` v3 and `Shodan_Honeyscore` analyzers.
- Added migration files for DB.

## [v1.4.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.4.0)

- Inbuilt Integration for [Pulsedive](pulsedive.com/) analyzer for IP, URL, Domain and Hash observables. Works without API key with rate limit of 30 requests/minute.
- Inbuilt integration for Integrated [Quark-engine](https://github.com/quark-engine/quark-engine) for APKs - _An Obfuscation-Neglect Android Malware Scoring System_.
- Increase `max_length` for `file_mimetype` column. Thanks to @skygrip for the report.
- Index the fields that are used in `ask_analysis_availability` for faster fetching.
- Update LDAP documentation, add section about GKE deployments.
- Fixed: `is_test` issue in `_docker_run`. Thanks to @colbyprior.
- Fixed: `active_dns` now returns proper result.
- The base docker image is now based on Python 3.7.
- Refactor test cases/classes to reduce duplicate code.

_For version prior to `v1.4.0`, you can directly refer to the releases tab._
