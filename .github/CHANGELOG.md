# Changelog

[**Upgrade Guide**](https://intelowl.readthedocs.io/en/latest/Installation.md#update-to-the-most-recent-version)
## [v4.2.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.2.1)

* Fixed Plugin bug which caused the inability to add new secrets.
* Fixed Yara Analyzer and added new open source rules
* Fixed Cape Sandbox analyzer not working
* Deprecated `ThreatMiner`, `SecurityTrails` and `Robtex` various analyzers and substituted with new versions.
* Refactoring and features in preparation to add support for cluster deployments.
* Added a new advanced Documentation section [Advanced Configuration](https://intelowl.readthedocs.io/en/latest/Advanced-Configuration.html)
  * Added more support for Cloud Deployments (in particular AWS)
* Other minor adjustments and fixes

## [v4.2.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.2.0)

With this release we welcome new official maintainers of IntelOwl:
- [Simone Berni](https://twitter.com/0ssig3no): Key Contributor and Backend Maintainer
- [Daniele Rosetti](https://github.com/drosetti): Key Contributor and Frontend Maintainer

These awesome guys will help us maintaining the project and will bring IntelOwl to the next level! 🚀
Be ready for new awesome features!

**Improved Document analysis**

We added some improvements to handle recent Microsoft Office downloaders:
* Now `Doc_Info` analyzer is able to extract URLs from samples that abuse [Follina](https://github.com/advisories/GHSA-4r9q-wqcj-x85j) vulnerability
* Now Microsoft Office analyzers does support OneNote documents
* We added [PyOneNote](https://github.com/DissectMalware/pyOneNote) analyzer to parse OneNote files.

**Deployments:**

We are preparing to add more support for production deployments. We added some [documentation](https://intelowl.readthedocs.io/en/latest/Installation.md) regarding:
* Logrotate Configuration
* Crontab Configuration

**New/Improved Analyzers:**

* Now `ClamAV` analyzer makes use of all open source un-official community rules, not only the official ones
* `Yara` performance should be greatly improved. We also added other open source repositories plus the chance to configure a private repository of your own.
* Added [DNS0_EU](https://docs.dns0.eu/) analyzer (DNS resolver `DNS0_EU` + detection of malicious domains `DNS0_EU_Malicious_Detector`)
* Added [CheckPhish](https://checkphish.ai/checkphish-api/) analyzer
* Added [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) analyzer
* Added [Koodous](https://docs.koodous.com/api/) analyzer
* Added [IPApi](https://ip-api.com) analyzer

**DEPRECATION WARNING:**

We have deprecated some analyzers and disabled them. We will remove them at the next major release.
If you want to still use their functionalities, you need to explicitly enable them again. But you should move to the new ones:
* Deprecated `Doc_Info_Experimental`. Its functionality (XLM Macro parsing) is moved to `Doc_Info`
* Deprecated `Strings_Info_Classic`. Please use `Strings_Info`
* Deprecated `Strings_Info_ML`. Please use `Strings_Info` and set the parameter `rank_strings` to `True`
* Deprecated all `Yara_Scan_<repo>` analyzers. They all went merged in the single `Yara` analyzer.

**Others**

- added testing suite for ReactJS Frontend
- tons of fixes, refactors and stability contributions
- a lot of dependencies upgrades

## [v4.1.5](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.5)
With this release we announce that IntelOwl Project will apply as a new Organization in the next [Google Summer of Code](https://summerofcode.withgoogle.com/)!

We have created a dedicated repository with all the info an aspiring contributor would need to participate to the program.

All open source and cyber security fans! We are calling you! Be the next contributor!

(...and under the hood we did some fixes and updates here and there)

## [v4.1.4](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.4)
With this release we welcome our first sponsor in [Open Collective](https://opencollective.com/intelowl-project): [ThreatHunter.ai](https://threathunter.ai/?utm_source=intelowl)! Thank you for your help!

Moreover this release solves a bug regarding the creation of organization-level secrets which was not possible before.

And this is the last release of this year for us! We will see each other back in 2023!

## [v4.1.3](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.3)
With this version we officially announce that we have joined [Open Collective](https://opencollective.com/intelowl-project) with the IntelOwl Project!

If you love this project and you would like to help us, we would love to get your support there!
<a href="https://opencollective.com/intelowl-project/donate" target="_blank">
  <img src="https://opencollective.com/intelowl-project/donate/button@2x.png?color=blue" width=150 />
</a>

**New/Improved Analyzers:**
* adjusted / fixed a lot of popular analyzers like Dehashed, MISP, VirusTotal, Alienvault OTX, PDF_Info and Unpacme
* fixed --malware_tools_analyzers broken

## [v4.1.2](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.2)

This version mainly adds quality improvements to the recently released ["Playbook" feature](https://intelowl.readthedocs.io/en/latest/Usage.html#playbooks):
* Now it is possible to create a new Playbook easily thanks to a proper button in the GUI. In this way you can save your own Playbooks and repeat them.
* Now Playbooks support the check of already existing similar analysis like normal analysis already do. This saves computational and analysts' time.

Thanks to @0x0elliot for these new features.

**New/Improved Analyzers:**
* VT analyzer has been fixed and works correctly when performing a "rescan" of a sample.
* AbuseIPDB analyzer does not show all the reports by default (this could become quite large)

**Others**
- various fixes and stability contributions
- a lot of dependencies upgrades

## [v4.1.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.1)

With the release we are happy to announce that we have finally deployed a public instance of IntelOwl, thanks to The Honeynet Project, available at https://intelowl.honeynet.org.

The access is not open to prevent abuse. If you are interested in getting access, please contact a member of The Honeynet Project and explain the reasons behind your interest.

Then, this release fixes some important bugs regarding the integration with OpenCTI and all the other optional DockerAnalyzers-based integrations which were not correctly working.

**Others**
- Several documentation adjustments and updates
- usual dependencies upgrades

## [v4.1.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.1.0)

This release marks the end of the Google Summer of Code for this year (2022)!
Each contributor wrote a blog post regarding his work for IntelOwl during this summer:
  - [Aditya Narayan Sinha](https://twitter.com/0x0elliot): [Creating Playbooks for IntelOwl](https://www.honeynet.org/2022/10/06/gsoc-2022-project-summary-creating-playbooks-for-intelowl/)
  - [Aditya Pratap Singh](https://twitter.com/devmrfitz): [IntelOwl v4 improvements](https://www.honeynet.org/2022/09/26/gsoc-2022-project-summary-intelowl-v4-improvements/)
  - [Hussain Khan](https://twitter.com/Hussain41099635): [IntelOwl Go Client](https://www.honeynet.org/2022/09/06/gsoc-2022-project-summary-intelowl-go-client-go-intelowl/)

I would like to thank them and all the mentors (@sp35, @eshaan7, @0ssigeno, @drosetti) for the efforts put in the place during the last months!

Looking forward for the Google Summer of Code 2023!

**Time savers features**
- New Plugin Type to allow to easily replicate the same type of analysis without having to select and/or configure groups of analyzers/connectors every time: **Playbooks** ([docs reference](https://intelowl.readthedocs.io/en/latest/Usage.html#playbooks))
- Default Plugins Parameters can be customized from the GUI and are defined at user/org level instead of globally ([docs reference](https://intelowl.readthedocs.io/en/latest/Advanced-Usage.html#customize-analyzer-execution))
- Plugins Secrets can now be managed from the GUI and are defined at user/org level instead of globally ([docs reference](https://intelowl.readthedocs.io/en/latest/Installation.html#deprecated-environment-configuration))
- Organization admins can enable/disable analyzers for all the org ([docs reference](https://intelowl.readthedocs.io/en/latest/Usage.html#multi-tenancy))
- Google Oauth authentication support ([docs reference](https://intelowl.readthedocs.io/en/latest/Advanced-Usage.html#google-oauth2))
- Added support for `extends` key to simplify Analyzer configuration and customization ([docs reference](https://intelowl.readthedocs.io/en/latest/Usage.html#analyzers-customization))

**Others**
- Adjusted default time limits and configuration of some analyzers
- various fixes and stability contributions
- a lot of dependencies upgrades
- other minor updates


## [v4.0.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.0.1)

**New/Improved Analyzers:**
- added pre-defined `Yara_Scan_Custom_Signatures` analyzer to give the chance to the users to add their own rules directly in IntelOwl.
- added `ELF_Info` analyzer which parses ELF files.
- added support for [TLSH](https://github.com/trendmicro/tlsh) hash in `File_Info` and telfhash in `ELF_Info`

**Fixes/Adjustments:**
- renamed `Yara_Scan_YARAify_Rules` to `Yara_Scan_YARAify`
- fixed `Yara_Scan_Community` update and extraction process
- a lot of dependencies upgrades
- fixed to the docs

## [v4.0.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v4.0.0)
**Notes:**

After months of work, we are finally ready to move forward and anticipate the new major 4.0.0 release for IntelOwl!

The GUI was completely rewritten by one of our maintainer, [Eshaan Bansal](https://twitter.com/eshaan7_), in ReactJS, and the code included in the main IntelOwl repository. This was possible thanks to the effort put in place by [Certego](https://www.certego.net/) in supporting the maintainers.

The overall user feeling should be drastically improved. We hope you'll enjoy the new appearance of IntelOwl! Please try it out and provide us feedback!

**NEW FEATURES**

While developing the new GUI, our main goal was to at least provide the same features that were available before. Anyway, we had the chance to add some important features:

- A new way to manage users and their permissions: the "Organization" feature. Please refer to the [docs here](https://intelowl.readthedocs.io/en/latest/Usage.md#organizations-and-user-management).
- A notification mechanism was added. Please refer to the [docs here](https://intelowl.readthedocs.io/en/latest/Usage.md#notifications).
- Now it is possible to do more advanced lookups through the Jobs History and have an overall better way to filter them.
- A new "API Access/Sessions" section was added to facilitate the management of API tokens and User sessions.
- Now it is possible to submit multiple observables / files at the same time.

**RETROCOMPATIBILITY INFO AND HOW TO UPDATE**

Please refer to the [**Upgrade Guide**](https://intelowl.readthedocs.io/en/latest/Installation.html#update-and-re-build)

**New/Improved Analyzers:**
- Added an analyzer which supports the new service provided for free by [The Honeynet Project](https://www.honeynet.org/2021/12/27/new-project-available-greedybear/): [GreedyBear](https://github.com/honeynet/GreedyBear) 
- Added 3 new analyzers for the new service from Abuse.ch: [YARAify](https://yaraify.abuse.ch/)
- Added support for PCAP files and a new analyzer for [Suricata](https://suricata.io/) which allows to analyze PCAPs with IDS rules very fast and at scale.

**Other:**

- improved and updated the overall documentation (in particular the [Contribute](https://intelowl.readthedocs.io/en/latest/Contribute.md) section) to help the developers to start to work on the project
- added DOCKER BUILDKIT, `--debug-build` and Watchman dependency to speed up development
- now the Backend and the Frontend are respectively highly dependant from 2 new open source projects created by [Certego](https://www.certego.net/), [certego-saas](https://github.com/certego/certego-saas) and [certego-ui](https://github.com/certego/certego-ui).
- a lot of dependencies upgrade, in particular in the new ReactJS Frontend.

## [v3.4.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.4.1)
**Notes:**

We are proud to announce that we have selected 3 contributors for the upcoming [Google Summer of Code](https://summerofcode.withgoogle.com/)!

IntelOwlProject will run their projects under the umbrella of [The Honeynet Project](https://www.honeynet.org/), like the previous years.

The contributors are going to have 3 intense months of work: with the help of the IntelOwl maintainers, they'll bring new functionalities to the project!

- [Aditya Narayan Sinha](https://twitter.com/0x0elliot): "Creating Playbooks for IntelOwl"
- [Aditya Pratap Singh](https://twitter.com/devmrfitz): "IntelOwl v4 improvements"
- [Hussain Khan](https://twitter.com/Hussain41099635): "IntelOwl Go Client"

We are also moving forward to release the next major version (v4). We just need to work on some update scripts.

**Fixes/Adjustments:**
* Add support for ".csv" file in all the Analyzers for documents
* Refactored `Triage` analyzers
* Fixes: #951, #1004, #1003
* usual dependencies upgrades


## [v3.4.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.4.0)
**New/Improved Analyzers:**
- Improved MISP analyzer: more options and fixed a bug (#979, #1000)
- Improved VT3 analyzers: now it is possible to extract relationships data + the analyzers are optimized to reduce the number of queries and save quota (#988)
- New [VirusTotal_v3_Intelligence_Search](https://developers.virustotal.com/reference/search) for premium users (#981)
- New [Yara_Scan_Bartblaze](https://github.com/bartblaze/Yara-rules) analyzer
- New [DocGuard](docguard.io) analyzer (#990)
- New [Anomali ThreatStream](threatstream.com) analyzer for premium users (#976)
- New [IntelX_Intelligent_Search](intelx.io) analyzer (it comes to complete the IntelX endpoints already available) (#974)

**Other:**
- some fixes #952, #938
- adjusted PR automation
- a lot of dependencies upgrades
- renamed `Yara_Scan_McAfee` analyzer to `Yara_Scan_Trellix` and `Virushee_UploadFile` to `Virushee_Upload_File`

## [v3.3.2](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.3.2)
**Notes:**

We are proud to announce two new sponsorships today!
   - [Milton Security](https://www.miltonsecurity.com?utm_source=intelowl)
   - [LimaCharlie](https://limacharlie.io/blog/limacharlie-sponsors-intel-owl/?utm_source=intelowl&utm_medium=banner)

If you are interested in helping the project through a donation, read [here](https://github.com/intelowlproject/IntelOwl/blob/master/.github/partnership_and_sponsors.md) how you can do it!

**New/Improved Analyzers:**
- New [CyberChef](https://gchq.githuba.io/CyberChef/) Analyzer! Run your own recipes in IntelOwl! Check the [docs](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#cyberchef)!

**Other:**
- fixes: [#931](https://github.com/intelowlproject/IntelOwl/issues/931)
- several dependencies upgrades


## [v3.3.1](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.3.1)

**Notes:**
- BREAKING CHANGE:
  - We merged some additional Docker Analyzers (`thug`, `static_analyzers`, `apk_analyzers`, `box-js` and `qiling`) into a single container called `malware_tools_analyzers`. In this way, the IntelOwl configuration with all those Malware Analyzers is a lot lighter than before. Just run `--malware_tools_analyzers` as a single option to leverage all those additional analyzers.
- fixed `--all_analyzers` and `--tor_analyzers` options not working.

**New/Improved Analyzers:**
- Added option to run shellcodes with Mandiant tools (Floss, SpeakEasy and Capa)
- Minor fix to [Qiling](https://github.com/qilingframework/qiling) Analyzers
- Added new Observable Analyzer for [Stalkphish](https://stalkphish.io)
- Added new Yara Analyzer for [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) Rules

**Other:**
- Added Issue Templates
- Renewed PR automation to better detect possible bugs in deployments and to improve performance

## [v3.3.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.3.0)

**Notes:**
- Added helper script that checks and installs [initial requirements](https://intelowl.readthedocs.io/en/develop/Installation.html#requirements). (`initialize.sh`)
- Added [RADIUS authentication support](https://intelowl.readthedocs.io/en/latest/Advanced-Usage.html#radius-authentication)

**New/Improved Analyzers:**
- Added a new optional [Docker Analyzer](https://intelowl.readthedocs.io/en/develop/Advanced-Usage.html#optional-analyzers) running [Onionscan](https://github.com/s-rah/onionscan)
- Added [CAPE Sandbox](https://capesandbox.com/) file analyzer
- `Doc_Info` analyzer now runs [msodde](https://github.com/decalage2/oletools/wiki/msodde) together with `olevba` and `XMLMacroDeobfuscator`
- `PE_Info` analyzer now calculates [impfuzzy](https://github.com/JPCERTCC/impfuzzy) and [dashicon](https://github.com/fr0gger/SuperPeHasher) hashes too.

**Other:**
- Added option to run ElasticSearch/Kibana together with IntelOwl with option `--elastic`. Check the [doc here](https://intelowl.readthedocs.io/en/latest/Advanced-Usage.html#example-configuration)
- Security: Patched Django Critical Bug + Added Brute Force protection to the Admin page
- Generic bug fixing and other maintenance work
- Bump some python dependencies


## [v3.2.4](https://github.com/intelowlproject/IntelOwl/releases/tag/v3.2.4)

**Notes:**

- The `Dragonfly_Emulation` analyzer will stop working without this update. Note that the output format (report JSON attributes) of this analyzer has had changes as well.

**New Analyzers:**

- `Virushee_Upload_File`: Check file hash and upload file sample for analysis on [Virushee API](https://api.virushee.com/).
- `Virushee_CheckHash`: Search for a previous analysis of a file by its hash (SHA256/SHA1/MD5) on [Virushee API](https://api.virushee.com/).
  > Setting the `VIRUSHEE_API_KEY` is optional to use these analyzers.

**Other:**

- A lot of code cleanliness. Thanks to @deepsource-autofix[bot].
- Make the `repo_downloader.sh` step optional during development using the `.env.start.test.template` file.
- Bump `pydragonfly` dependency for `Dragonfly_Emulation` analyzer.
- Bump some python dependencies.

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
- VirusTotal v3: New configuration options: `include_behaviour_summary` for behavioral analysis and `include_sigma_analyses` for sigma analysis report of the file. See [Customize Analyzers](https://intelowl.readthedocs.io/en/master/Advanced-Usage.html#customize-analyzer-execution).

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
