# Introduction

Official announcement: [Certego News](https://www.certego.net/en/news/new-year-new-tool-intel-owl/)

IntelOwl was designed with the intent to help the community, in particular those researchers that can not afford commercial solutions, in the generation of threat intelligence data, in a simple, scalable and reliable way.

Main features:

* modern Django-Python application: easy to understand and write code upon it
* it can get data from multiple sources with a single API request
* about 100 available analyzers that you can use to generate or retrieve data about a suspicious file or observable (IP, domain, …)
* Built-in Web Interface: **[IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng)** provides features such as dashboard, visualizations of analysis data, easy to use forms for requesting new analysis and more.
* official library and CLI client available on Github: [PyIntelOwl](https://github.com/intelowlproject/pyintelowl)
* easily integrable with other tools thanks to the REST API framework and to the PyIntelOwl library.
* easily and completely customizable, both the APIs and the analyzers
* early compatibility with some of the AWS services. More in the future.
* fast and reliable deploy: clone the project, set up the configuration and then you are ready to run it via docker-compose


Feel free to ask everything it comes to your mind about the project to the author:
Matteo Lodi ([Twitter](https://twitter.com/matte_lodi)).

We also have a dedicated twitter account for the project: [@intel_owl](https://twitter.com/intel_owl).