# Changelog

[**Upgrade Guide**](https://intelowl.readthedocs.io/en/latest/Installation.html#update-to-the-most-recent-version)

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
    * `ActiveDNS_Classic` -> `Classic_DNS`
    * `ActiveDNS_CloudFlare` -> `CloudFlare_DNS`
    * `ActiveDNS_CloudFlare_Malware` -> `CloudFlare_Malicious_Detector`
    * `ActiveDNS_Google` -> `Google_DNS`


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
* Added [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) analyzer, refer #196 thanks to @0ssigeno 
* Updated oletools to last available changes

Other:
* updated black to 20.8b1 and little fix in the docs

## [v1.7.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.7.0)

- 3 new analyzers which can be used out of the box:
   * `UnpacMe_EXE_Unpacker`: [UnpacMe](https://www.unpac.me/) is an automated malware unpacking service. (Thanks to @0ssigeno)
   * `CheckDMARC`: [checdmarc](https://github.com/domainaware/checkdmarc) provides SPF and DMARC DNS records validator for domains. (Thanks to @goodlandsecurity)
   * `Whoisxmlapi`: Fetch WHOIS record data, of a domain name, an IP address, or an email address. (Thanks to @tamthaitu) 
- Some fixes to Cymru Malware and VT2 analyzers.
- Now you or your organization can get paid support/extra features/custom integrations for IntelOwl via xscode platform. [Details](https://xscode.com/intelowlproject/IntelOwl).

## [v1.6.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.1)

This patch allows to download the most recent docker image of IntelOwl. Previous version was downloading the old (`v1.5.1`) docker image.

Please see [v1.6.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.0) for release details.

## [v1.6.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.6.0)

* added new analyzer for [FireEye speakeasy](https://github.com/fireeye/speakeasy)
* updated [FireEye Capa](https://github.com/fireeye/capa) to 1.1.0
* updated docs, including instructions for [Remnux](https://docs.remnux.org) users and a new ["How to use pyintelowl" video](https://www.youtube.com/watch?v=fpd6Kt9EZdI).

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
- Inbuilt integration for Integrated [Quark-engine](https://github.com/quark-engine/quark-engine) for APKs - *An Obfuscation-Neglect Android Malware Scoring System*.
- Increase `max_length` for `file_mimetype` column. Thanks to @skygrip for the report.
- Index the fields that are used in `ask_analysis_availability` for faster fetching.
- Update LDAP documentation, add section about GKE deployments.
- Fixed: `is_test` issue in `_docker_run`. Thanks to @colbyprior.
- Fixed: `active_dns` now returns proper result.
- The base docker image is now based on Python 3.7.
- Refactor test cases/classes to reduce duplicate code.


_For version prior to `v1.4.0`, you can directly refer to the releases tab._