<img src="static/intel_owl_positive.png" width=547 height=150 alt="Intel Owl"/>

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/intelowlproject/IntelOwl)](https://github.com/intelowlproject/IntelOwl/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/intelowlproject/IntelOwl?style=social)](https://github.com/intelowlproject/IntelOwl/stargazers)
[![Docker](https://img.shields.io/docker/pulls/intelowlproject/intelowl)](https://hub.docker.com/repository/docker/intelowlproject/intelowl)
[![Twitter Follow](https://img.shields.io/twitter/follow/intel_owl?style=social)](https://twitter.com/intel_owl)
[![Linkedin](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/intelowl/)
[![Official Site](https://img.shields.io/badge/official-site-blue)](https://intelowlproject.github.io)
[![Live Instance](https://img.shields.io/badge/live-demo-blue)](https://intelowl.honeynet.org)

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![CodeQL](https://github.com/intelowlproject/IntelOwl/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions/workflows/codeql-analysis.yml)
[![Dependency Review](https://github.com/intelowlproject/IntelOwl/actions/workflows/dependency_review.yml/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions/workflows/dependency_review.yml)
[![Build & Tests](https://github.com/intelowlproject/IntelOwl/workflows/Build%20&%20Tests/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions)
[![DeepSource](https://app.deepsource.com/gh/intelowlproject/IntelOwl.svg/?label=resolved+issues&token=BSvKHrnk875Y0Bykb79GNo8w)](https://app.deepsource.com/gh/intelowlproject/IntelOwl/?ref=repository-badge)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intelowlproject/IntelOwl/badge)](https://api.securityscorecards.dev/projects/github.com/intelowlproject/IntelOwl)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/7120/badge)](https://bestpractices.coreinfrastructure.org/projects/7120)
# Intel Owl

Do you want to get **threat intelligence data** about a malware, an IP address or a domain? Do you want to get this kind of data from multiple sources at the same time using **a single API request**?

You are in the right place!

IntelOwl is an Open Source solution for management of Threat Intelligence at scale. It integrates a number of analyzers available online and a lot of cutting-edge malware analysis tools.

### Features
This application is built to **scale out** and to **speed up the retrieval of threat info**.

It provides:
- **Enrichment of Threat Intel** for files as well as observables (IP, Domain, URL, hash, etc).
- A Fully-fledged REST APIs written in Django and Python.
- An easy way to be integrated in your stack of security tools to automate common jobs usually performed, for instance, by SOC analysts manually. (Thanks to the official libraries [pyintelowl](https://github.com/intelowlproject/pyintelowl) and [go-intelowl](https://github.com/intelowlproject/go-intelowl))
- A **built-in GUI**: provides features such as dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, etc.
- A **framework** composed of modular components called **Plugins**:
  - *analyzers* that can be run to either retrieve data from external sources (like VirusTotal or AbuseIPDB) or to generate intel from internally available tools (like Yara or Oletools)
  - *connectors* that can be run to export data to external platforms (like MISP or OpenCTI)
  - *pivots* that are designed to trigger the execution of a chain of analysis and connect them to each other
  - *visualizers* that are designed to create custom visualizations of analyzers results in the GUI
  - *ingestors* that allow to automatically ingest stream of observables or files to IntelOwl itself
  - *playbooks* that are meant to make analysis easily repeatable
  - *data models* to map the different data extracted from analyzers to a single common schema
- A starting point for analysts' **Investigations**: users can register their findings, correlate the information found, and collaborate...all in a single place


### Documentation
We try hard to keep our documentation well written, easy to understand and always updated.
All info about installation, usage, configuration and contribution can be found [here](https://intelowlproject.github.io/docs/)

### Publications and Media

To know more about the project and its growth over time, you may be interested in reading [the official blog posts and/or videos about the project by clicking on this link](https://intelowlproject.github.io/docs/IntelOwl/introduction/#publications-and-media)

### Available services or analyzers

You can see the full list of all available analyzers in the [documentation](https://intelowlproject.github.io/docs/IntelOwl/usage/#analyzers).

| Type                                               | Analyzers Available                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Inbuilt modules                                    | - Static Office Document, RTF, PDF, PE, ELF, APK File Analysis and metadata extraction<br/> - Strings Deobfuscation and analysis ([FLOSS](https://github.com/mandiant/flare-floss), [Stringsifter](https://github.com/mandiant/stringsifter), ...)<br/> - [Yara](https://virustotal.github.io/yara/), [ClamAV](https://www.clamav.net/) (a lot of public rules are available. You can also add your own rules)<br/> - PE Emulation with [Qiling](https://github.com/qilingframework/qiling) and [Speakeasy](https://github.com/mandiant/speakeasy)<br/> - PE Signature verification<br/> - PE Capabilities Extraction ([CAPA](https://github.com/mandiant/capa) and [Blint](https://github.com/owasp-dep-scan/blint))<br/> - Javascript Emulation ([Box-js](https://github.com/CapacitorSet/box-js))<br/> - Android Malware Analysis ([Quark-Engine](https://github.com/quark-engine/quark-engine), [Androguard](https://github.com/androguard/androguard), [Mobsf](https://github.com/MobSF/mobsfscan/), ...)<br/> - SPF and DMARC Validator<br/> - PCAP Analysis with [Suricata](https://github.com/OISF/suricata) and [Hfinger](https://github.com/CERT-Polska/hfinger) <br/> - Honeyclients ([Thug](https://github.com/buffer/thug), [Selenium](https://github.com/wkeeling/selenium-wire)) <br/> - Scanners ([WAD](https://github.com/CERN-CERT/WAD), [Nuclei](https://github.com/projectdiscovery/nuclei), ...) <br/> - more... |
| External services                                  | - Abuse.ch <a href="https://bazaar.abuse.ch/about/" target="_blank">MalwareBazaar</a>/<a href="https://urlhaus.abuse.ch/" target="_blank">URLhaus</a>/<a href="https://threatfox.abuse.ch/about/" target="_blank">Threatfox</a>/<a href="https://yaraify.abuse.ch/about/" target="_blank">YARAify</a></br> - <a href="https://docs.greynoise.io/docs/3rd-party-integrations" target="_blank"> GreyNoise v2</a><br/> - <a href="https://analyze.intezer.com/?utm_source=IntelOwl" target="_blank"> Intezer</a><br/> - VirusTotal v3<br/> - <a href="https://doc.crowdsec.net/docs/next/cti_api/integration_intelowl/?utm_source=IntelOwl" target="_blank"> Crowdsec</a><br/> - <a href="https://urlscan.io/docs/integrations/" target="_blank">URLscan</a><br/> - Shodan<br/> - AlienVault OTX<br/> - <a href="https://intelx.io/integrations" target="_blank">Intelligence_X</a><br/> - <a href="https://www.misp-project.org/" target="_blank">MISP</a><br/> - many more..                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

## Partnerships and sponsors

As open source project maintainers, we strongly rely on external support to get the resources and time to work on keeping the project alive, with a constant release of new features, bug fixes and general improvements.

Because of this, we joined [Open Collective](https://opencollective.com/intelowl-project) to obtain US and EU non-profit equal level status which allows the organization to receive and manage donations transparently and with tax exemption. Please support IntelOwl and all the community by choosing a plan (BRONZE, SILVER, etc).

<a href="https://opencollective.com/intelowl-project/donate" target="_blank">
  <img src="https://opencollective.com/intelowl-project/donate/button@2x.png?color=blue" width=200 />
</a>

#### Certego

<a href="https://certego.net/?utm_source=intelowl"> <img style="margin-right: 2px" width=250 height=71 src="static/Certego.png" alt="Certego Logo"/></a>

[Certego](https://certego.net/?utm_source=intelowl) is a MDR (Managed Detection and Response) and Threat Intelligence Provider based in Italy.

IntelOwl was born out of Certego's Threat intelligence R&D division and is mostly maintained and updated thanks to them.

#### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=125 height=125 src="static/honeynet_logo.png" alt="Honeynet.org logo"> </a>

[The Honeynet Project](https://www.honeynet.org) is a non-profit organization working on creating open source cyber security tools and sharing knowledge about cyber threats.

Thanks to Honeynet, we are hosting a public demo of the application [here](https://intelowl.honeynet.org). If you are interested, please contact a member of Honeynet or an IntelOwl maintainer to get access to the public service.

#### Google Summer of Code
<a href="https://summerofcode.withgoogle.com/"> <img style="border: 0.2px solid black" width=150 height=89 src="static/gsoc_logo.png" alt="GSoC logo"> </a>

Since its birth this project has been participating in the [Google Summer of Code](https://summerofcode.withgoogle.com/) (GSoC)!

If you are interested in participating in the next Google Summer of Code, check all the info available in the [dedicated repository](https://github.com/intelowlproject/gsoc)!


#### Docker

In 2021 IntelOwl joined the official [Docker Open Source Program](https://www.docker.com/blog/expanded-support-for-open-source-software-projects/). This allows IntelOwl developers to easily manage Docker images and focus on writing the code. You may find the official IntelOwl Docker images [here](https://hub.docker.com/search?q=intelowlproject).

#### DigitalOcean

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=128f2c68f93b&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

In 2022 IntelOwl joined the official [DigitalOcean Open Source Program](https://www.digitalocean.com/open-source?utm_medium=opensource&utm_source=IntelOwl).


## About the author and maintainers

Feel free to contact the main developers at any time on Twitter:

- [Matteo Lodi](https://twitter.com/matte_lodi): Author, Advisor and Administrator
- [Daniele Rosetti](https://github.com/drosetti): Administrator and Frontend Maintainer
- [Simone Berni](https://twitter.com/0ssig3no): Backend Maintainer
- [Federico Gibertoni](https://x.com/fgibertoni1): Maintainer and Community Assistant
- [Eshaan Bansal](https://twitter.com/eshaan7_): Key Contributor