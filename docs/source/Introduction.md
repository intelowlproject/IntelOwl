# Introduction

IntelOwl was designed with the intent to help the community, in particular those researchers that can not afford commercial solutions, in the generation of threat intelligence data, in a simple, scalable and reliable way.

Main features:

- Provides enrichment of Threat Intel for malware as well as observables (IP, Domain, URL, hash, etc).
- This application is built to **scale out** and to **speed up the retrieval of threat info**.
- Thanks to the official libraries [pyintelowl](https://github.com/intelowlproject/pyintelowl) and [go-intelowl](https://github.com/intelowlproject/go-intelowl), it can be integrated easily in your stack of security tools to automate common jobs usually performed, for instance, by SOC analysts manually.
- Intel Owl is composed of:
  - **analyzers** that can be run to either retrieve data from external sources (like VirusTotal or AbuseIPDB) or to generate intel from internally available tools (like Yara or Oletools)
  - **connectors** that can be run to export data to external platforms (like MISP or OpenCTI)
  - **visualizers** that can be run to create custom visualizations of analyzers results
  - **playbooks** that are meant to make analysis easily repeatable
- API REST written in Django and Python 3.9.
- Built-in frontend client written in ReactJS, with **[certego-ui](https://github.com/certego/certego-ui)**: provides features such as dashboard, visualizations of analysis data, easy to use forms for requesting new analysis, etc.

## Publications and media
To know more about the project and its growth over time, you may be interested in reading the following official blog posts and/or videos:

- [The Honeynet Workshop: Denmark 2024](https://github.com/intelowlproject/thp_workshop_2024)
- [Certego Blog: v6 Announcement (in Italian)](https://www.certego.net/blog/intelowl-six-release/)
- [HackinBo 2023 Presentation (in Italian)](https://www.youtube.com/watch?v=55GKEZoDBgU)
- [Certego Blog: v.5.0.0 Announcement](https://www.certego.net/blog/intelowl-v5-released)
- [Youtube demo: IntelOwl v4](https://youtu.be/pHnh3qTzSeM)
- [Certego Blog: v.4.0.0 Announcement](https://www.certego.net/en/news/intel-owl-release-v4-0-0/)
- [Honeynet Blog: v3.0.0 Announcement](https://www.honeynet.org/2021/09/13/intel-owl-release-v3-0-0/)
- [Intel Owl on Daily Swig](https://portswigger.net/daily-swig/intel-owl-osint-tool-automates-the-intel-gathering-process-using-a-single-api)
- [Honeynet Blog: v1.0.0 Announcement](https://www.honeynet.org/?p=7558)
- [Certego Blog: First announcement](https://www.certego.net/en/news/new-year-new-tool-intel-owl/)

Feel free to ask everything it comes to your mind about the project to the author:
Matteo Lodi ([Twitter](https://twitter.com/matte_lodi)).

We also have a dedicated twitter account for the project: [@intel_owl](https://twitter.com/intel_owl).