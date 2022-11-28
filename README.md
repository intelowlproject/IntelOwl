<img src="docs/static/intel_owl_positive.png" width=547 height=150 alt="Intel Owl"/>

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/intelowlproject/IntelOwl)](https://github.com/intelowlproject/IntelOwl/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/intelowlproject/IntelOwl?style=social)](https://github.com/intelowlproject/IntelOwl/stargazers)
[![Docker](https://img.shields.io/docker/pulls/intelowlproject/intelowl)](https://hub.docker.com/repository/docker/intelowlproject/intelowl)
[![Twitter Follow](https://img.shields.io/twitter/follow/intel_owl?style=social)](https://twitter.com/intel_owl)
[![Linkedin](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/intelowl/)
[![Official Site](https://img.shields.io/badge/official-site-blue)](https://intelowlproject.github.io)
[![Live Demo](https://img.shields.io/badge/live-demo-blue)](https://intelowl.honeynet.org)

[![CodeFactor](https://www.codefactor.io/repository/github/intelowlproject/intelowl/badge)](https://www.codefactor.io/repository/github/intelowlproject/intelowl)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![CodeQL](https://github.com/intelowlproject/IntelOwl/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions/workflows/codeql-analysis.yml)
[![Dependency Review](https://github.com/intelowlproject/IntelOwl/actions/workflows/dependency_review.yml/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions/workflows/dependency_review.yml)
[![Build & Tests](https://github.com/intelowlproject/IntelOwl/workflows/Build%20&%20Tests/badge.svg)](https://github.com/intelowlproject/IntelOwl/actions)
[![codecov](https://codecov.io/gh/intelowlproject/IntelOwl/branch/master/graph/badge.svg?token=R097M4TYA6)](https://codecov.io/gh/intelowlproject/IntelOwl)
# Intel Owl

Do you want to get **threat intelligence data** about a malware, an IP or a domain? Do you want to get this kind of data from multiple sources at the same time using **a single API request**?

You are in the right place!

Intel Owl is an Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale. It integrates a number of analyzers available online and a lot of cutting-edge malware analysis tools. It is for everyone who needs a single point to query for info about a specific file or observable.

### Features

- Provides enrichment of Threat Intel for malware as well as observables (IP, Domain, URL, hash, etc).
- This application is built to **scale out** and to **speed up the retrieval of threat info**.
- It can be integrated easily in your stack of security tools ([pyintelowl](https://github.com/intelowlproject/pyintelowl)) to automate common jobs usually performed, for instance, by SOC analysts manually.
- Intel Owl is composed of:
  - **analyzers** that can be run to retrieve data from external sources (like VirusTotal or AbuseIPDB) or to generate intel from internally available tools (like Yara or Oletools)
  - **connectors** that can be run to export data to external platforms
- API REST written in Django and Python 3.9.
- Built-in frontend client written in ReactJS, with **[certego-ui](https://github.com/certego/certego-ui)**: provides features such as dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, etc.

## Documentation [![Documentation Status](https://readthedocs.org/projects/intelowl/badge/?version=latest)](https://intelowl.readthedocs.io/en/latest/?badge=latest)

Documentation about IntelOwl installation, usage, configuration and contribution can be found at https://intelowl.readthedocs.io/.

## Blog posts

To know more about the project and it's growth over time, you may be interested in reading the following:

- [Certego Blog: v.4.0.0 Announcement](https://www.certego.net/en/news/intel-owl-release-v4-0-0/)
- [Honeynet: v3.0.0 Announcement](https://www.honeynet.org/2021/09/13/intel-owl-release-v3-0-0/)
- [Intel Owl on Daily Swig](https://portswigger.net/daily-swig/intel-owl-osint-tool-automates-the-intel-gathering-process-using-a-single-api)
- [Honeynet: v1.0.0 Announcement](https://www.honeynet.org/?p=7558)
- [Certego Blog: First announcement](https://www.certego.net/en/news/new-year-new-tool-intel-owl/)

## Available services or analyzers

You can see the full list of all available analyzers in the [documentation](https://intelowl.readthedocs.io/en/latest/Usage.html#available-analyzers).

| Type                                               | Analyzers Available                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------------------------------------- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Inbuilt modules                                    | - Static Office Document, RTF, PDF, PE File Analysis and metadata extraction<br/> - Strings Deobfuscation and analysis ([FLOSS](https://github.com/mandiant/flare-floss), [Stringsifter](https://github.com/mandiant/stringsifter), ...)<br/> - PE Emulation with [Qiling](https://github.com/qilingframework/qiling) and [Speakeasy](https://github.com/mandiant/speakeasy)<br/> - PE Signature verification<br/> - PE Capabilities Extraction ([CAPA](https://github.com/mandiant/capa))<br/> - Javascript Emulation ([Box-js](https://github.com/CapacitorSet/box-js))<br/> - Android Malware Analysis ([Quark-Engine](https://github.com/quark-engine/quark-engine), ...)<br/> - SPF and DMARC Validator<br/> - more...                                                                                                              |
| External services                                  | - <a href="https://dragonfly.certego.net?utm_source=intelowl" target="_blank">Dragonfly malware sandbox</a><br> - Abuse.ch <a href="https://bazaar.abuse.ch/about/" target="_blank">MalwareBazaar</a>/<a href="https://threatfox.abuse.ch/about/" target="_blank">Threatfox</a>/<a href="https://yaraify.abuse.ch/about/" target="_blank">YARAify</a></br> - <a href="https://docs.greynoise.io/docs/3rd-party-integrations" target="_blank"> GreyNoise v2</a><br/> - <a href="https://analyze.intezer.com/?utm_source=IntelOwl" target="_blank"> Intezer</a><br/> - VirusTotal v2+v3<br/> - HybridAnalysis<br/> - <a href="https://urlscan.io/docs/integrations/" target="_blank">URLscan</a><br/> - Shodan<br/> - AlienVault OTX<br/> - <a href="https://intelx.io/integrations" target="_blank">Intelligence_X</a><br/> - many more.. |
| Free modules that require additional configuration | - Cuckoo (requires at least one working Cuckoo instance)<br/> - MISP (requires at least one working MISP instance)<br/> - Yara (a lot of public rules area available. There's also the chance to add your own rules)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## Partnerships and sponsors

As open source project maintainers, we strongly rely on external support to get the resources and time to work on keeping the project alive, with a constant release of new features, bug fixes and general improvements.

Because of this, we joined [Open Collective](https://opencollective.com/intelowl-project) to obtain non-profit equal level status which allows the organization to receive and manage donations transparently. Please support IntelOwl and all the community by choosing a plan (BRONZE, SILVER, etc).

<a href="https://opencollective.com/intelowl-project/donate" target="_blank">
  <img src="https://opencollective.com/intelowl-project/donate/button@2x.png?color=blue" width=200 />
</a>

### 🥇 GOLD

#### Certego

<a href="https://certego.net/?utm_source=intelowl"> <img style="margin-right: 2px" width=250 height=71 src="docs/static/Certego.png" alt="Certego Logo"/></a>

[Certego](https://certego.net/?utm_source=intelowl) is a MDR (Managed Detection and Response) and Threat Intelligence Provider based in Italy.

IntelOwl was born out of Certego's Threat intelligence R&D division and is constantly maintained and updated thanks to them.

> [Dragonfly](https://dragonfly.certego.net/?utm_source=intelowl), an automated sandbox to emulate and analyze malware, is a new public service by Certego developed by the same team behind IntelOwl. It is now available as the `Dragonfly_Emulation` analyzer in IntelOwl. [Sign up](https://dragonfly.certego.net/register?utm_source=intelowl) on Dragonfly today for free access!

#### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=125 height=125 src="docs/static/honeynet_logo.png" alt="Honeynet.org logo"> </a>

[The Honeynet Project](https://www.honeynet.org) is a non-profit organization working on creating open source cyber security tools and sharing knowledge about cyber threats.

Thanks to Honeynet, we are hosting a public demo of the application [here](https://intelowl.honeynet.org). If you are interested, please contact a member of Honeynet to get access to the public service.

Since its birth, under the umbrella of this organization, this project has been participating in the [Google Summer of Code](https://summerofcode.withgoogle.com/) (GSoC)!

Project Summaries and/or in-development projects:

- 2020: (Mentor: Matteo Lodi)
  - [Eshaan Bansal](https://twitter.com/eshaan7_): [IntelOwl Work Product](https://www.honeynet.org/2020/08/26/gsoc-2020-work-product%e2%80%8a-%e2%80%8aintel-owl/)
- 2021: (New mentor: Eshaan Bansal)
  - [Sarthak Khattar](https://twitter.com/Mr_Momo07): [IntelOwl Improvements](https://www.honeynet.org/2021/08/20/gsoc-2021-project-summary-intelowl-improvements/)
  - [Shubham Pandey](https://twitter.com/imshubham31): [IntelOwl Connectors Manager and Integrations](https://www.honeynet.org/2021/08/20/gsoc-2021-project-summary-intelowl-connectors-manager-and-integrations/)
- 2022: (New mentors: Shubham Pandey, Simone Berni, Daniele Rosetti)
  - [Aditya Narayan Sinha](https://twitter.com/0x0elliot): [Creating Playbooks for IntelOwl](https://www.honeynet.org/2022/10/06/gsoc-2022-project-summary-creating-playbooks-for-intelowl/)
  - [Aditya Pratap Singh](https://twitter.com/devmrfitz): [IntelOwl v4 improvements](https://www.honeynet.org/2022/09/26/gsoc-2022-project-summary-intelowl-v4-improvements/)
  - [Hussain Khan](https://twitter.com/Hussain41099635): [IntelOwl Go Client](https://www.honeynet.org/2022/09/06/gsoc-2022-project-summary-intelowl-go-client-go-intelowl/)
- 2023: you?

~~If you are interested in being the next GSoC developer for IntelOwl, join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.~~

Since 2023 we are proposing IntelOwl and [GreedyBear](https://github.com/honeynet/GreedyBear) to the GSoC under a new non-profit organization called [IntelOwl Project](https://www.linkedin.com/company/intelowl) and not anymore under the Honeynet Project. Because of that, if you are interested in being the next GSoC developer for us, we invite you to join this new [Slack channel](https://intelowlproject.slack.com).

This is also the place where the majority of the development discussion happens, so feel free to join, have a look and ask questions about the project.

### 🥈 SILVER

#### Milton Security

<a href="https://www.miltonsecurity.com?utm_source=intelowl"> <img style="border: 0.2px solid black" width=120 height=38 src="docs/static/milton_logo.png" alt="Milton Security logo"> </a>

[Milton Security](https://www.miltonsecurity.com?utm_source=intelowl)  is a Service Disabled Veteran Owned Small Business that provides effective Threat Hunting and Incident Response to organizations around the globe 24*7

### 🥉 BRONZE

#### LimaCharlie
<a href="https://limacharlie.io/?utm_source=intelowl&utm_medium=banner"> <img style="border: 0.2px solid black" width=194 height=38 src="docs/static/limacharlie_logo.png" alt="LimaCharlie logo"> </a>

[LimaCharlie](https://limacharlie.io/?utm_source=intelowl&utm_medium=banner) gives security teams full control over how they manage their security infrastructure. Get full visibility into your coverage, build what you want, control your data, get the security capabilities you need, for however long you need them, and pay only for what you use.

Read everything about this partnership [in the LimaCharlie's blog](https://limacharlie.io/blog/limacharlie-sponsors-intel-owl/?utm_source=intelowl&utm_medium=banner).

#### Tines

<a href="https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=intelowl"> <img style="border: 0.2px solid black" width=120 height=55 src="docs/static/tines_logo.png" alt="Tines logo"> </a>

[Tines](https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=intelowl) is no-code automation for security teams. Build powerful, reliable workflows without a development team.

IntelOwl is officially integrated in Tines. Read everything about this partnership [in the Tines' blog](https://www.tines.com/blog/announcing-our-sponsorship-of-intel-owl?utm_source=oss&utm_medium=sponsorship&utm_campaign=intelowl).

#### Docker

<a href="https://www.docker.com"> <img style="border: 0.2px solid black" width=120 height=31 src="docs/static/docker_logo.png" alt="Docker logo"> </a>

In 2021 IntelOwl joined the official [Docker Open Source Program](https://www.docker.com/blog/expanded-support-for-open-source-software-projects/). This allows IntelOwl developers to easily manage Docker images and focus on writing the code. You may find the official IntelOwl Docker images [here](https://hub.docker.com/search?q=intelowlproject).

### 🤝 IRON

If you are an individual who likes this project and want to thank us with a little contribution, we would be happy to list you here in the README as a public acknowledgment.

## About the author and maintainers

Feel free to contact the main developers at any time on twitter:

- [Matteo Lodi](https://twitter.com/matte_lodi): Author and creator
- [Eshaan Bansal](https://twitter.com/eshaan7_): Principal maintainer
