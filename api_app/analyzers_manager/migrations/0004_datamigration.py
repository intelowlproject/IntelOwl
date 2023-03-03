analyzers = {
  "APKiD_Scan_APK_DEX_JAR": {
    "type": "file",
    "python_module": "apkid.APKiD",
    "description": "APKiD identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file.",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": [
      "application/zip",
      "application/java-archive",
      "application/vnd.android.package-archive",
      "application/x-dex",
      "android"
    ],
    "config": {
      "soft_time_limit": 400,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "AbuseIPDB": {
    "type": "observable",
    "python_module": "abuseipdb.AbuseIPDB",
    "description": "check if an ip was reported on [AbuseIPDB](https://www.abuseipdb.com/)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "ABUSEIPDB_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "max_age": {
        "value": 180,
        "type": "int",
        "description": "How many days back you want to check for reports. Default 180"
      },
      "max_reports": {
        "value": 200,
        "type": "int",
        "description": "How many reports you want to save. Default 200"
      },
      "verbose": {
        "value": True,
        "type": "bool",
        "description": "Reports are included in this response if you enable this flag. Omitting the verbose flag will exclude reports and the country name field. If you want to keep your response payloads light, this is recommended"
      }
    }
  },
  "Anomali_Threatstream_Confidence": {
    "type": "observable",
    "python_module": "threatstream.Threatstream",
    "disabled": False,
    "description": "Analyzer for threatstream API Confidence, give max, average and min confidence of entries for an observable",
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_user_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_USER",
        "type": "str",
        "required": True,
        "description": "API USER for Anomali Threatstream"
      },
      "api_key_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for Anomali Threatstream"
      }
    },
    "params": {
      "threatstream_analysis": {
        "value": "confidence",
        "type": "str",
        "description": "API in threatstream called is Confidence one"
      }
    }
  },
  "Anomali_Threatstream_Intelligence": {
    "type": "observable",
    "python_module": "threatstream.Threatstream",
    "disabled": False,
    "description": "Analyzer for threatstream API Intelligence (main threat intelligence information)",
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_user_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_USER",
        "type": "str",
        "required": True,
        "description": "API USER for Anomali Threatstream"
      },
      "api_key_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for Anomali Threatstream"
      }
    },
    "params": {
      "threatstream_analysis": {
        "value": "intelligence",
        "type": "str",
        "description": "API in threatstream called is Intelligence one"
      },
      "limit": {
        "value": "100",
        "type": "str",
        "description": "Number of maximal entries returned"
      },
      "must_active": {
        "value": False,
        "type": "bool",
        "description": "Only return active entries"
      },
      "minimal_confidence": {
        "value": "0",
        "type": "str",
        "description": "Minimal Confidence filter"
      },
      "modified_after": {
        "value": "1900-10-02T20:44:35",
        "type": "str",
        "description": "Filter on entries modified after a specific date. Date must be specified in this format: YYYYMMDDThhmmss where T denotes the start of the value for time, in UTC time. For example, 2014-10-02T20:44:35."
      }
    }
  },
  "Anomali_Threatstream_PassiveDNS": {
    "type": "observable",
    "python_module": "threatstream.Threatstream",
    "disabled": False,
    "description": "Return information from passive dns of Anomali.",
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_user_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_USER",
        "type": "str",
        "required": True,
        "description": "API USER for Anomali Threatstream"
      },
      "api_key_name": {
        "env_var_key": "ANOMALI_THREATSTREAM_API_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for Anomali Threatstream"
      }
    },
    "params": {
      "threatstream_analysis": {
        "value": "passive_dns",
        "type": "str",
        "description": "API in threatstream called is passive_dns one"
      }
    }
  },
  "Auth0": {
    "type": "observable",
    "python_module": "auth0.Auth0",
    "description": "scan an IP against the Auth0 API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "AUTH0_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "BinaryEdge": {
    "type": "observable",
    "python_module": "binaryedge.BinaryEdge",
    "description": "Details about an Host. List of recent events for the specified host, including details of exposed ports and services and return list of subdomains known from the target domains",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip","domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "BINARYEDGE_KEY",
        "description": "API key for the BinaryEdge",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "BitcoinAbuse": {
    "type": "observable",
    "python_module": "bitcoinabuse.BitcoinAbuseAPI",
    "description": "Check a BTC address against bitcoinabuse.com, a public database of BTC addresses used by hackers and criminals.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "BITCOINABUSE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "BoxJS_Scan_JavaScript": {
    "type": "file",
    "python_module": "boxjs_scan.BoxJS",
    "description": "A tool for studying JavaScript malware",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": [
      "application/x-javascript",
      "application/javascript",
      "text/javascript"
    ],
    "config": {
      "soft_time_limit": 400,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "CheckDMARC": {
    "type": "observable",
    "python_module": "checkdmarc.CheckDMARC",
    "description": "An SPF and DMARC DNS records validator",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "CheckPhish": {
    "type": "observable",
    "python_module": "checkphish.CheckPhish",
    "description": "[CheckPhish](https://checkphish.ai/checkphish-api/) can detect phishing and fraudulent sites",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "observable_supported": ["url"],
    "config": {
      "soft_time_limit": 100,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "CHECKPHISH_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for the analyzer"
      }
    },
    "params": {
      "polling_tries": {
        "value": 10,
        "type": "int",
        "description": "How many times we poll the CheckPhish API for scan results"
      },
      "polling_time": {
        "value": 0.5,
        "type": "float",
        "description": "IntelOwl would sleep for this time between each poll to CheckPhish APIs"
      }
    }
  },
  "CIRCLPassiveDNS": {
    "type": "observable",
    "python_module": "circl_pdns.CIRCL_PDNS",
    "description": "scan an observable against the CIRCL Passive DNS DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "pdns_credentials": {
        "env_var_key": "CIRCL_CREDENTIALS",
        "description": "Template to use: `<user>|<pwd>`.",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "CIRCLPassiveSSL": {
    "type": "observable",
    "python_module": "circl_pssl.CIRCL_PSSL",
    "description": "scan an observable against the CIRCL Passive SSL DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "pdns_credentials": {
        "env_var_key": "CIRCL_CREDENTIALS",
        "description": "Template to use: `<user>|<pwd>`.",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Classic_DNS": {
    "type": "observable",
    "python_module": "dns.dns_resolvers.classic_dns_resolver.ClassicDNSResolver",
    "description": "Retrieve current domain resolution with default DNS",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query_type": {
        "value": "A",
        "type": "str",
        "description": "Query type against the chosen DNS resolver."
      }
    }
  },
  "CloudFlare_DNS": {
    "type": "observable",
    "python_module": "dns.dns_resolvers.cloudflare_dns_resolver.CloudFlareDNSResolver",
    "description": "Retrieve current domain resolution with CloudFlare DoH (DNS over HTTPS)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query_type": {
        "value": "A",
        "type": "str",
        "description": ""
      }
    }
  },
  "CloudFlare_Malicious_Detector": {
    "type": "observable",
    "python_module": "dns.dns_malicious_detectors.cloudflare_malicious_detector.CloudFlareMaliciousDetector",
    "description": "Scan an observable against CloudFlare DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Crowdsec": {
    "type": "observable",
    "python_module": "crowdsec.Crowdsec",
    "description": "check if an IP was reported on [Crowdsec](https://www.crowdsec.net/) Smoke Dataset",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "CROWDSEC_KEY",
        "description": "API Key to access the service",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Capa_Info": {
    "type": "file",
    "python_module": "capa_info.CapaInfo",
    "description": "capa detects capabilities in executable files",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/x-dosexec",
      "application/x-sharedlib",
      "application/x-executable",
      "application/x-elf"
    ],
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "arch": {
        "value": "64",
        "description": "`32` or `64`",
        "type": "str"
      },
      "shellcode": {
        "value": False,
        "description": "if the file analyzed is a shellcode or not",
        "type": "bool"
      }
    }
  },
  "Capa_Info_Shellcode": {
    "type": "file",
    "python_module": "capa_info.CapaInfo",
    "description": "capa detects capabilities in shellcode files",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/octet-stream"],
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "arch": {
        "value": "64",
        "type": "str",
        "description": "Change system architecture for the shellcode (32 or 64)."
      },
      "shellcode": {
        "value": True,
        "type": "bool",
        "description": "true if the file is a shellcode."
      }
    }
  },
  "CapeSandbox": {
    "type": "file",
    "python_module": "cape_sandbox.CAPEsandbox",
    "description": "Automatic scan of suspicious files using [CapeSandbox](https://github.com/kevoreilly/CAPEv2) API",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "docker_based": False,
    "config": {
      "soft_time_limit": 1000,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "CAPESANDBOX_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "CAPESANDBOX_URL",
        "description": "URL for the CapeSandbox instance. If none provided, It uses the API provided by CAPESandbox by default.",
        "default": "https://www.capesandbox.com",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "VM_NAME": {
        "value": "",
        "type": "str",
        "description": "The VM to be used in the analysis."
      },
      "max_tries": {
        "value": 50,
        "type": "int",
        "description": "Number of max tries while trying to poll the CAPESandbox API."
      },
      "poll_distance": {
        "value": 30,
        "type": "int",
        "description": "Seconds to wait before moving on to the next poll attempt."
      }
    }
  },
  "Censys_Search": {
    "type": "observable",
    "python_module": "censys.Censys",
    "description": "scan an IP address against Censys View API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_id_name": {
        "env_var_key": "CENSYS_API_ID",
        "description": "",
        "required": True,
        "type": "str"
      },
      "api_secret_name": {
        "env_var_key": "CENSYS_API_SECRET",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "censys_analysis": {
        "value": "search",
        "type": "str",
        "description": ""
      }
    }
  },
  "ClamAV": {
    "type": "file",
    "python_module": "clamav.ClamAV",
    "description": "scan files using [ClamAV AntiVirus Engine](https://www.clamav.net/). IntelOwl automatically keep ClamAV updated with official and [unofficial](https://github.com/rseichter/fangfrisch) open source signatures",
    "disabled": False,
    "leaks_info": False,
    "external_service": False,
    "docker_based": True,
    "config": {
      "soft_time_limit": 70,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "CryptoScamDB_CheckAPI": {
    "type": "observable",
    "python_module": "cryptoscamdb.CryptoScamDB",
    "description": "Scan a cryptocurrency address, IP address, domain or ENS name against the [CryptoScamDB](https://cryptoscamdb.org/) API.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "generic"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "CRXcavator": {
    "type": "observable",
    "python_module": "crxcavator.CRXcavator",
    "description": "Scans a chrome extension against crxcavator.io service. Every Chrome-Extension has a unique alpha=numeric identifier. That's the only Input necessary. Eg: `Norton Safe Search Enhanced`'s identifier is `eoigllimhcllmhedfbmahegmoakcdakd`.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Cuckoo_Scan": {
    "type": "file",
    "python_module": "cuckoo_scan.CuckooAnalysis",
    "description": "scan a file on a Cuckoo instance",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "CUCKOO_API_KEY",
        "description": "",
        "required": False,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "CUCKOO_URL",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "max_post_tries": {
        "value": 5,
        "type": "int",
        "description": ""
      },
      "max_poll_tries": {
        "value": 20,
        "type": "int",
        "description": ""
      }
    }
  },
  "CyberChef": {
    "type": "observable",
    "python_module": "cyberchef.CyberChef",
    "description": "Bake an input with a selected CyberChef Recipe",
    "disabled": False,
    "observable_supported": ["generic"],
    "external_service": False,
    "config": {
      "soft_time_limit": 50,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "recipe_name": {
        "value": "to decimal",
        "type": "str",
        "description": "Name of pre-defined recipe to use."
      },
      "recipe_code": {
        "value": [],
        "type": "list",
        "description": "Custom recipe to use (instead of a predefined one). [Here](https://github.com/mattnotmax/cyberchef-recipes) are some sample recipes. NOTE: This is only read if recipe_name is blank"
      },
      "output_type": {
        "value": "",
        "type": "str",
        "description": "Output type of the recipe. Leave blank to use default. Available output types are listed [here](https://github.com/gchq/CyberChef/wiki/Adding-a-new-operation#data-types)"
      }
    }
  },
  "Cymru_Hash_Registry_Get_File": {
    "type": "file",
    "python_module": "cymru.Cymru",
    "description": "Check if a particular file is known to be malware by Team Cymru",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Cymru_Hash_Registry_Get_Observable": {
    "type": "observable",
    "python_module": "cymru.Cymru",
    "description": "Check if a particular hash is available in the malware hash registry of Team Cymru",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Darksearch_Query": {
    "type": "observable",
    "python_module": "darksearch.DarkSearchQuery",
    "description": "Query against [darksearch](https://darksearch.io/api/search)'s API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 50,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "pages": {
        "value": 10,
        "type": "int",
        "description": ""
      },
      "proxies": {
        "value": {},
        "type": "dict",
        "description": ""
      }
    }
  },
  "Dehashed_Search": {
    "type": "observable",
    "python_module": "dehashed.DehashedSearch",
    "description": "Query against Dehashed's search API. For configuration, refer to the 'Sizing & Pagination' section in [dehashed docs](https://www.dehashed.com/docs).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 300,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "DEHASHED_AUTH_KEY",
        "description": "Combination of your dehashed account's email and API key. Format: `email:api-key`.",
        "required": True
      }
    },
    "params": {
      "size": {
        "value": 100,
        "type": "int",
        "description": "Number of records fetched. Recommend change to a large value."
      },
      "pages": {
        "value": 1,
        "type": "int",
        "description": "Number of pages fetched. Recommend to keep at 1 only to save on credits."
      },
      "operator": {
        "value": "username",
        "type": "str",
        "description": "Search Operator to use among (id, email, ip_address, username, password, hashed_password, hash_type, name, vin, address, phone, database_name). Default: username"
      }
    }
  },
  "DNS0_EU": {
    "type": "observable",
    "python_module": "dns.dns_resolvers.dns0_eu_resolver.DNS0EUResolver",
    "description": "Retrieve current domain resolution with DNS0.eu DoH (DNS over HTTPS)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query_type": {
        "value": "A",
        "type": "str",
        "description": "Query type against the chosen DNS resolver."
      }
    }
  },
  "DNS0_EU_Malicious_Detector": {
    "type": "observable",
    "python_module": "dns.dns_malicious_detectors.dns0_eu_malicious_detector.DNS0EUMaliciousDetector",
    "description": "Check if a domain or an url is marked as malicious in DNS0.eu database ([Zero](https://www.dns0.eu/zero) service)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "DNSDB": {
    "type": "observable",
    "python_module": "dnsdb.DNSdb",
    "description": "Scan an observable against the Passive DNS Farsight Database (support both v1 and v2 versions). Official [API docs](https://docs.dnsdb.info/dnsdb-apiv2/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url", "ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "DNSDB_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "server": {
        "value": "api.dnsdb.info",
        "type": "str",
        "description": "DNSDB server."
      },
      "api_version": {
        "value": 2,
        "type": "int",
        "description": "API version of DNSDB (options: `1` and `2`)."
      },
      "rrtype": {
        "value": "",
        "type": "str",
        "description": "DNS query type."
      },
      "limit": {
        "value": 10000,
        "type": "int",
        "description": "Maximum number of results to retrieve."
      },
      "time": {
        "value": {
          "first_before": "",
          "first_after": "",
          "last_before": "",
          "last_after": ""
        },
        "type": "dict",
        "description": "Time range"
      },
      "query_type": {
        "value": "domain",
        "type": "str",
        "description": "Query type. Options: domain (default), rrname-wildcard-left, rrname-wildcard-right, names, rdata-wildcard-left, rdata-wildcard-right"
      }
    }
  },
  "DNStwist": {
    "type": "observable",
    "python_module": "dnstwist.DNStwist",
    "description": "scans for potentially malicious permutations of a domain name",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "tld": {
        "value": True,
        "type": "bool",
        "description": "Check for domains with different TLDs by supplying a dictionary file."
      },
      "tld_dict": {
        "value": "abused_tlds.dict",
        "type": "str",
        "description": "Dictionary to use with `tld` argument (`common_tlds.dict/abused_tlds.dict`)."
      },
      "mxcheck": {
        "value": True,
        "type": "bool",
        "description": "Find suspicious mail servers and flag them with SPYING-MX string."
      },
      "ssdeep": {
        "value": True,
        "type": "bool",
        "description": "Enable fuzzy hashing - compare HTML content of original domain with a potentially malicious one and determine similarity."
      }
    }
  },
  "Doc_Info": {
    "type": "file",
    "python_module": "doc_info.DocInfo",
    "description": "static Microsoft Office document analysis ([Oletools](https://github.com/decalage2/oletools)) with features to analyze XLM macros, encrypted macros and much more",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/msword",
      "application/vnd.ms-office",
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-powerpoint",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/onenote",
      "text/x-ms-iqy",
      "application/excel",
      "text/xml",
      "application/xml",
      "application/zip",
      "application/encrypted",
      "text/plain",
      "text/csv"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "additional_passwords_to_check": {
        "value": [""],
        "type": "list",
        "description": "List of passwords to try when decrypting the document"
      }
    }
  },
  "Doc_Info_Experimental": {
    "type": "file",
    "python_module": "doc_info.DocInfo",
    "description": "static Microsoft Office document analysis with new features to analyze XLM macros, encrypted macros and more [DEPRECATED, move to Doc_Info]",
    "disabled": True,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/msword",
      "application/vnd.ms-office",
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-powerpoint",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "text/x-ms-iqy",
      "application/excel",
      "text/xml",
      "application/xml",
      "application/zip",
      "application/encrypted",
      "text/plain",
      "text/csv"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "experimental": {
        "value": True,
        "type": "bool",
        "description": ""
      },
      "additional_passwords_to_check": {
        "value": [],
        "type": "list",
        "description": "List of passwords to try when decrypting the document"
      }
    }
  },
  "DocGuard_Get": {
    "type": "observable",
    "python_module": "docguard_get.DocGuard_Hash",
    "description": "check if an hash was analyzed on DocGuard. [DocGuard](https://www.docguard.io)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "DOCGUARD_KEY",
        "description": "",
        "required": False,
        "type": "str"
      }
    },
    "params": {}
  },
  "DocGuard_Upload_File": {
    "type": "file",
    "python_module": "docguard.DocGuardUpload",
    "description": "Analyze office files in seconds. [DocGuard](https://www.docguard.io) Please register and use api-key to your privacy",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "supported_filetypes": [
      "application/msword",
      "application/vnd.ms-office",
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-powerpoint",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/onenote",
      "text/x-ms-iqy",
      "application/excel",
      "text/xml",
      "application/xml",
      "application/zip",
      "application/encrypted",
      "text/plain",
      "text/csv"
    ],
    "config": {
      "soft_time_limit": 180,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "DOCGUARD_KEY",
        "description": "",
        "required": False,
        "type": "str"
      }
    },
    "params": {}
  },
  "Dragonfly_Emulation": {
    "type": "file",
    "python_module": "dragonfly.DragonflyEmulation",
    "description": "Emulate malware against [Dragonfly](https://dragonfly.certego.net/?utm_source=intelowl) sandbox by [Certego S.R.L](https://certego.net).",
    "supported_filetypes": [
      "application/x-dosexec",
      "application/octet-stream"
    ],
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "config": {
      "soft_time_limit": 400,
      "queue": "long"
    },
    "params": {
      "profiles": {
        "value": [1, 2],
        "type": "list",
        "description": "List of profile indices for emulators. Refer to [profiles list](https://dragonfly.certego.net/dashboard/profiles?utm_source=intelowl)."
      },
      "operating_system": {
        "value": "",
        "type": "str",
        "description": "Enum: `WINDOW`|`LINUX`| or leave blank string for automatic detection"
      },
      "root": {
        "value": False,
        "type": "bool",
        "description": "If `true`, emulate with root permissions"
      },
      "allow_actions": {
        "value": False,
        "type": "bool",
        "description": "If `true`, run actions when a rule matches"
      },
      "private": {
        "value": False,
        "type": "bool",
        "description": "If `true`, mark the analysis as private so it's accessible to you and members within your organization only"
      }
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "DRAGONFLY_API_KEY",
        "description": "Dragonfly API key. Generate [here](https://dragonfly.certego.net/me/sessions?utm_source=intelowl).",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "DRAGONFLY_API_URL",
        "description": "Dragonfly instance URL. Don't change this.",
        "default": "https://dragonfly.certego.net/",
        "required": True,
        "type": "str"
      }
    }
  },
  "ELF_Info": {
    "type": "file",
    "python_module": "elf_info.ELFInfo",
    "description": "static ELF analysis",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/x-sharedlib",
      "application/x-elf",
      "application/x-executable"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "EmailRep": {
    "type": "observable",
    "python_module": "emailrep.EmailRep",
    "description": "Get email reputation from emailrep.io",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["generic"],
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "EMAILREP_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "File_Info": {
    "type": "file",
    "python_module": "file_info.FileInfo",
    "description": "basic static analysis, extracts metadata (with [Exiftools](https://exiftool.org/)) and hashes",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "FireHol_IPList": {
    "type": "observable",
    "python_module": "firehol_iplist.FireHol_IPList",
    "description": "Check if an IP is in FireHol's IPList. Refer to [FireHol's IPList](https://iplists.firehol.org/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 180,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "list_names": {
        "value": ["firehol_level1.netset"],
        "type": "list",
        "description": "A list of firehol list names."
      }
    }
  },
  "FileScan_Upload_File": {
    "type": "file",
    "python_module": "filescan.FileScanUpload",
    "description": "Extract IoCs from executable files, documents and scripts via [FileScan.io API](https://www.filescan.io/api/docs).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "config": {
      "soft_time_limit": 180,
      "queue": "long"
    },
    "secrets": {},
    "params": {}
  },
  "FileScan_Search": {
    "type": "observable",
    "python_module": "filescan_search.FileScanSearch",
    "description": "Finds reports and uploaded files by various tokens, like hash, filename, verdict, IOCs etc via [FileScan.io API](https://www.filescan.io/api/docs).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["url", "domain", "ip", "generic", "hash"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Floss": {
    "type": "file",
    "python_module": "floss.Floss",
    "description": "Advanced String Extraction by FireEye",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": [
      "application/x-dosexec",
      "application/octet-stream"
    ],
    "config": {
      "soft_time_limit": 500,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "max_no_of_strings": {
        "value": {
          "stack_strings": 1000,
          "static_strings": 1000,
          "decoded_strings": 1000
        },
        "type": "dict",
        "description": ""
      },
      "rank_strings": {
        "value": {
          "stack_strings": False,
          "static_strings": False,
          "decoded_strings": False
        },
        "type": "dict",
        "description": ""
      }
    }
  },
  "Google_DNS": {
    "type": "observable",
    "python_module": "dns.dns_resolvers.google_dns_resolver.GoogleDNSResolver",
    "description": "Retrieve current domain resolution with Google DoH (DNS over HTTPS)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query_type": {
        "value": "A",
        "type": "str",
        "description": "Query type against the chosen DNS resolver."
      }
    }
  },
  "GoogleWebRisk": {
    "type": "observable",
    "python_module": "dns.dns_malicious_detectors.google_webrisk.WebRisk",
    "description": "Scan an observable against Web Risk API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url"],
    "config": {
      "soft_time_limit": 20,
      "queue": "default"
    },
    "secrets": {
      "service_account_json": {
        "env_var_key": "SERVICE_ACCOUNT_JSON",
        "description": "service account file in JSON format",
        "required": True,
        "type": "dict"
      }
    },
    "params": {}
  },
  "GoogleSafebrowsing": {
    "type": "observable",
    "python_module": "dns.dns_malicious_detectors.googlesf.GoogleSF",
    "description": "Scan an observable against GoogleSafeBrowsing DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "GSF_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "GreedyBear": {
    "type": "observable",
    "python_module": "greedybear.GreedyBear",
    "description": "scan an IP or a domain against the [GreedyBear](https://www.honeynet.org/2021/12/27/new-project-available-greedybear/) service",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": [
      "ip", "domain"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "GREEDYBEAR_API_KEY",
        "description": "API key required for authentication",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "url": {
        "value": "https://greedybear.honeynet.org",
        "type": "str",
        "description": "URL of the GreedyBear instance you want to connect to"
      }
    }
  },
  "GreyNoise": {
    "type": "observable",
    "python_module": "greynoiseintel.GreyNoiseAnalyzer",
    "description": "scan an IP against the Greynoise API (requires API key)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "GREYNOISE_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "greynoise_api_version": {
        "value": "v2",
        "type": "str",
        "description": "[GreyNoise Enterprise API](https://docs.greynoise.io/docs/using-the-greynoise-api)"
      }
    }
  },
  "GreyNoiseCommunity": {
    "type": "observable",
    "python_module": "greynoiseintel.GreyNoiseAnalyzer",
    "description": "scan an IP against the Community Greynoise API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "secrets": {
      "api_key_name": {
        "env_var_key": "GREYNOISE_API_KEY",
        "description": "",
        "required": False,
        "type": "str",
        "default": ""
      }
    },
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "params": {
      "greynoise_api_version": {
        "value": "v3",
        "type": "str",
        "description": "[GreyNoise Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api)"
      }
    }
  },
  "HashLookupServer_Get_Observable": {
    "type": "observable",
    "python_module": "hashlookup.HashLookupServer",
    "description": "check if a md5 or sha1 is available in the database of known file hosted by CIRCL",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 20,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "hashlookup_server": {
        "value": "",
        "type": "str",
        "description": "custom hashlookup-server"
      }
    }
  },
  "HashLookupServer_Get_File": {
    "type": "file",
    "python_module": "hashlookup.HashLookupServer",
    "description": "check if a md5 or sha1 is available in the database of known file hosted by CIRCL",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "not_supported_filetypes": [
      "application/msword",
      "application/vnd.ms-office",
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-powerpoint",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/onenote",
      "text/x-ms-iqy",
      "application/excel",
      "text/xml",
      "application/xml",
      "application/zip",
      "application/encrypted"
    ],
    "config": {
      "soft_time_limit": 40,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "hashlookup_server": {
        "value": "",
        "type": "str",
        "description": "custom hashlookup-server"
      }
    }
  },
  "HaveIBeenPwned": {
    "type": "observable",
    "python_module": "haveibeenpwned.HaveIBeenPwned",
    "description": "Check if an email address has been involved in a data breach",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "observable_supported": ["generic"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "HIBP_API_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for HaveIBeenPwned"
      }
    },
    "params": {
      "truncate_response": {
        "value": True,
        "type": "bool",
        "description": "Truncate response to only include most recent data breaches"
      },
      "include_unverified": {
        "value": False,
        "type": "bool",
        "description": "Include unverified data breaches in the response"
      },
      "domain": {
        "value": "",
        "type": "str",
        "description": "Search for data breaches specific to a domain"
      }
    }
  },
  "HoneyDB": {
    "type": "observable",
    "python_module": "honeydb.HoneyDB",
    "description": "HoneyDB IP lookup service",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 200,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "HONEYDB_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "api_id_name": {
        "env_var_key": "HONEYDB_API_ID",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "honeydb_analysis": {
        "value": "all",
        "type": "str",
        "description": "Choose which endpoint to query from the HoneyDB service (options are: `all`, `scan_twitter`, `ip_query`, `ip_history`, `internet_scanner`, `ip_info`)"
      }
    }
  },
  "Hunter": {
    "type": "observable",
    "python_module": "hunter.Hunter",
    "description": "Scans a domain name and returns set of data about the organisation, the email address found and additional information about the people owning those email addresses",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "HUNTER_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "HybridAnalysis_Get_File": {
    "type": "file",
    "python_module": "ha_get.HybridAnalysisGet",
    "description": "check file hash on HybridAnalysis sandbox reports",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "HA_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "HybridAnalysis_Get_Observable": {
    "type": "observable",
    "python_module": "ha_get.HybridAnalysisGet",
    "description": "search an observable in the HybridAnalysis sandbox reports",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "HA_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "IntelX_Intelligent_Search": {
    "type": "observable",
    "python_module": "intelx.IntelX",
    "description": "Intelligent search against IntelX API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 45,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INTELX_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "query_type": {
        "value": "intelligent",
        "type": "str",
        "description": "Query Type. Choose between 'playbook' and 'intelligent'"
      },
      "rows_limit": {
        "value": 1000,
        "type": "int",
        "description": "max number of results to retrieve"
      },
      "datefrom": {
        "value": "",
        "type": "str",
        "description": "use this in combination with 'dateto' to filter the query"
      },
      "dateto": {
        "value": "",
        "type": "str",
        "description": "use this in combination with 'datefrom' to filter the query"
      },
      "timeout": {
        "value": 10,
        "type": "int",
        "description": ""
      },
      "max_tries": {
        "value": 10,
        "type": "int",
        "description": ""
      },
      "poll_distance": {
        "value": 3,
        "type": "int",
        "description": ""
      }
    }
  },
  "IntelX_Phonebook": {
    "type": "observable",
    "python_module": "intelx.IntelX",
    "description": "Phonebook alike search against IntelX API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 45,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INTELX_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "query_type": {
        "value": "phonebook",
        "type": "str",
        "description": "Query Type. Choose between 'playbook' and 'intelligent'"
      },
      "rows_limit": {
        "value": 1000,
        "type": "int",
        "description": "max number of results to retrieve"
      },
      "timeout": {
        "value": 10,
        "type": "int",
        "description": ""
      },
      "max_tries": {
        "value": 10,
        "type": "int",
        "description": ""
      },
      "poll_distance": {
        "value": 3,
        "type": "int",
        "description": ""
      }
    }
  },
  "Intezer_Get": {
    "type": "observable",
    "python_module": "intezer_get.IntezerGet",
    "description": "check if an hash was analyzed on Intezer. Register for a free community account [here](https://analyze.intezer.com/sign-in?utm_source=IntelOwl).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INTEZER_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "soft_time_limit": {
        "value": 100,
        "type": "int",
        "description": ""
      }
    }
  },
  "Intezer_Scan": {
    "type": "file",
    "python_module": "intezer_scan.IntezerScan",
    "description": "Scan a file on Intezer. Register for a free community account [here](https://analyze.intezer.com/sign-in?utm_source=IntelOwl).",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "supported_filetypes": [
      "application/x-dosexec",
      "application/x-executable",
      "application/x-elf",
      "application/zip",
      "application/java-archive",
      "application/vnd.android.package-archive",
      "application/x-dex",
      "application/msword",
      "application/vnd.ms-office",
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-powerpoint",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/onenote",
      "text/x-ms-iqy",
      "application/excel",
      "text/xml",
      "application/xml",
      "application/encrypted",
      "text/plain",
      "text/csv"
    ],
    "config": {
      "soft_time_limit": 300,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INTEZER_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "upload_file": {
        "value": True,
        "type": "bool",
        "description": "Uploads the analyzed file to Intezer in case an analysis of that file is not available in that platform."
      },
      "disable_dynamic_unpacking": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "disable_static_unpacking": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "soft_time_limit": {
        "value": 300,
        "type": "int",
        "description": ""
      }
    }
  },
  "InQuest_IOCdb": {
    "type": "observable",
    "python_module": "inquest.InQuest",
    "description": "Indicators of Compromise Database - search IOCdb",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INQUEST_API_KEY",
        "description": "",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "inquest_analysis": {
        "value": "iocdb_search",
        "description": "",
        "type": "str"
      }
    }
  },
  "InQuest_REPdb": {
    "type": "observable",
    "python_module": "inquest.InQuest",
    "description": "Reputation Database - search REPdb",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INQUEST_API_KEY",
        "description": "",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "inquest_analysis": {
        "value": "repdb_search",
        "type": "str",
        "description": ""
      }
    }
  },
  "InQuest_DFI": {
    "type": "observable",
    "python_module": "inquest.InQuest",
    "description": "Deep File Inspection - search dfi",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "INQUEST_API_KEY",
        "description": "",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "inquest_analysis": {
        "value": "dfi_search",
        "type": "str",
        "description": ""
      }
    }
  },
  "IPApi": {
    "type": "observable",
    "python_module": "ipapi.IPApi",
    "description": "Gives information about [IPs](https://ip-api.com/docs/api:batch) and [DNS](https://ip-api.com/docs/dns)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "fields" : {
        "value" : "",
        "type" : "str",
        "description" : "specify the information fields"
      },
      "lang" : {
        "value" : "",
        "type" : "str",
        "description" : "specify the response language"
      }
    }
  },
  "IPInfo": {
    "type": "observable",
    "python_module": "ipinfo.IPInfo",
    "description": "Brief Information regarding given IP",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "IPINFO_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Koodous": {
    "type": "observable", 
    "python_module": "koodous.Koodous",
    "description": "Get information about android malware",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"], 
    "config": {
      "soft_time_limit": 100,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "KOODOUS_KEY",
        "type": "str",
        "required": True,
        "description": "API Key for the Koodous analyzer"
      }
    },
    "params": {}
},
  "Manalyze": {
    "type": "file",
    "python_module": "manalyze.Manalyze",
    "description": "A static analyzer for PE files",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 180,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "MISP": {
    "type": "observable",
    "python_module": "misp.MISP",
    "description": "scan an observable on a custom MISP instance",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MISP_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "MISP_URL",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "ssl_check": {
        "value": True,
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled"
      },
      "self_signed_certificate": {
        "value": False,
        "type": "bool",
        "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)"
      },
      "debug": {
        "value": False,
        "type": "bool",
        "description": "Enable debug logs."
      },
      "from_days": {
        "value": 90,
        "type": "int",
        "description": "Check only events created in the past X days. 0 for no filter"
      },
      "limit": {
        "value": 50,
        "type": "int",
        "description": "Limit the number of results returned"
      },
      "filter_on_type": {
        "value": True,
        "type": "bool",
        "description": "Filter the search on the type of the observable."
      },
      "enforce_warninglist": {
        "value": True,
        "type": "bool",
        "description": "Remove any attributes from the result that would cause a hit on a warninglist entry."
      },
      "strict_search": {
        "value": True,
        "type": "bool",
        "description": "Search strictly on the observable value (True) or search on attributes containing observable value (False)"
      }
    }
  },
  "MISPFIRST": {
    "type": "observable",
    "python_module": "misp.MISP",
    "description": "scan an observable on the FIRST MISP instance",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "FIRST_MISP_API",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "FIRST_MISP_URL",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "ssl_check": {
        "value": True,
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled"
      },
      "self_signed_certificate": {
        "value": False,
        "type": "bool",
        "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)"
      },
      "debug": {
        "value": False,
        "type": "bool",
        "description": "Enable debug logs."
      },
      "from_days": {
        "value": 90,
        "type": "int",
        "description": "Check only events created in the past X days. 0 for no filter"
      },
      "limit": {
        "value": 50,
        "type": "int",
        "description": "Limit the number of results returned"
      },
      "filter_on_type": {
        "value": True,
        "type": "bool",
        "description": "Filter the search on the type of the observable."
      },
      "enforce_warninglist": {
        "value": True,
        "type": "bool",
        "description": "Remove any attributes from the result that would cause a hit on a warninglist entry."
      },
      "strict_search": {
        "value": True,
        "type": "bool",
        "description": "Search strictly on the observable value (True) or search on attributes containing observable value (False)"
      }
    }
  },
  "MISPFIRST_Check_Hash": {
    "type": "file",
    "python_module": "misp.MISP",
    "description": "check a file hash on the FIRST MISP instance",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "FIRST_MISP_API",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "FIRST_MISP_URL",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "MISP_Check_Hash": {
    "type": "file",
    "python_module": "misp.MISP",
    "description": "check a file hash on a MISP instance",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MISP_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "MISP_URL",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Malpedia_Scan": {
    "type": "file",
    "python_module": "malpedia_scan.MalpediaScan",
    "description": "scan a binary or a zip file (pwd:infected) against all the yara rules available in Malpedia",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "supported_filetypes": [
      "application/x-binary",
      "application/x-dosexec",
      "application/x-executable",
      "application/x-elf",
      "application/x-macbinary",
      "application/mac-binary",
      "application/octet-stream",
      "application/zip",
      "application/x-zip-compressed",
      "application/x-compressed",
      "multipart/x-zip"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MALPEDIA_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "MalwareBazaar_Get_File": {
    "type": "file",
    "python_module": "mb_get.MB_GET",
    "description": "Check if a particular malware sample is known to MalwareBazaar",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "MalwareBazaar_Get_Observable": {
    "type": "observable",
    "python_module": "mb_get.MB_GET",
    "description": "Check if a particular malware hash is known to MalwareBazaar",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "MalwareBazaar_Google_Observable": {
    "type": "observable",
    "python_module": "mb_google.MB_GOOGLE",
    "description": "Check if a particular IP, domain or url is known to MalwareBazaar using google search",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "MaxMindGeoIP": {
    "type": "observable",
    "python_module": "maxmind.Maxmind",
    "description": "extract GeoIP info for an IP",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MAXMIND_KEY",
        "description": "API key to access the service",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "MWDB_Get": {
    "type": "observable",
    "python_module": "mwdb_get.MWDBGet",
    "description": "check if an hash was analyzed on MWDB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 20,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MWDB_KEY",
        "description": "",
        "required": True
      }
    },
    "params": {}
  },
  "MWDB_Scan": {
    "type": "file",
    "python_module": "mwdb_scan.MWDB_Scan",
    "description": "Scan a file against MWDB by Cert Polska",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "config": {
      "soft_time_limit": 400,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MWDB_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "upload_file": {
        "value": True,
        "type": "bool",
        "description": "Uploads the file to repository."
      },
      "private": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "max_tries": {
        "value": 50,
        "type": "int",
        "description": "Number of retries to perform for polling analysis results."
      }
    }
  },
  "OneNote_Info": {
    "type": "file",
    "python_module": "onenote.OneNoteInfo",
    "description": "Extracting information from OneNote Office docs via [PyOneNote](https://github.com/DissectMalware/pyOneNote)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/onenote"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "ONYPHE": {
    "type": "observable",
    "python_module": "onyphe.Onyphe",
    "description": "search an observable in the ONYPHE",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url"],
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "ONYPHE_KEY",
        "description": "",
        "required": True
      }
    },
    "params": {}
  },
  "OpenCTI": {
    "type": "observable",
    "python_module": "opencti.OpenCTI",
    "description": "scan an observable on a custom OpenCTI instance",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "OPENCTI_KEY",
        "description": "API key for your OpenCTI instance",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "OPENCTI_URL",
        "description": "URL of your OpenCTI instance",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "ssl_verify": {
        "value": True,
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your OpenCTI instance has not SSL enabled."
      },
      "proxies": {
        "value": {
          "http": "",
          "https": ""
        },
        "type": "dict",
        "description": "Use these options to pass your request through a proxy server."
      },
      "exact_search": {
        "value": False,
        "type": "bool",
        "description": "Use this if you want exact matches only for the observables returned."
      }
    }
  },
  "OTXQuery": {
    "type": "observable",
    "python_module": "otx.OTX",
    "description": "scan an observable on Alienvault OTX",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "OTX_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "verbose": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "sections": {
        "value": ["general"],
        "type": "list",
        "description": "Data are divided into sections, list of sections to download"
      },
      "full_analysis": {
        "value": False,
        "type": "bool",
        "description": "download all the available sections for the observable type"
      }
    }
  },
  "OTX_Check_Hash": {
    "type": "file",
    "python_module": "otx.OTX",
    "description": "check file hash on OTX Alienvault",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "OTX_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "verbose": {
        "value": False,
        "type": "bool",
        "description": ""
      }
    }
  },
  "Mnemonic_PassiveDNS": {
    "type": "observable",
    "python_module": "mnemonic_pdns.MnemonicPassiveDNS",
    "description": "Look up a domain or IP using the [Mnemonic PassiveDNS public API](https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "ip"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "cof_format": {
        "value": True,
        "type": "bool",
        "description": "Return result in the PassiveDNS [Common Output Format](https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/)."
      },
      "limit": {
        "value": 1000,
        "type": "int",
        "description": "Number of records to fetch."
      }
    }
  },
  "PDF_Info": {
    "type": "file",
    "python_module": "pdf_info.PDFInfo",
    "description": "static PDF analysis (peepdf + pdfid)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/pdf"],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "PE_Info": {
    "type": "file",
    "python_module": "pe_info.PEInfo",
    "description": "static PE analysis (pefile)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "PEframe_Scan": {
    "type": "file",
    "python_module": "peframe.PEframe",
    "description": "Perform static analysis on Portable Executable malware and malicious MS Office documents",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 500,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "Phishstats": {
    "type": "observable",
    "python_module": "phishstats.PhishStats",
    "description": "Search PhishStats API to determine if an IP/URL/domain is malicious.",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "observable_supported": ["ip", "url", "domain", "generic"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Phishtank": {
    "type": "observable",
    "python_module": "phishtank.Phishtank",
    "description": "Check if url is verified in [Phishtank](https://phishtank.com/) API.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["url"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "PHISHTANK_API_KEY",
        "description": "Optional API key.",
        "required": False,
        "type": "str"
      }
    },
    "params": {}
  },
  "Pulsedive": {
    "type": "observable",
    "python_module": "pulsedive.Pulsedive",
    "description": "Scan indicators and retrieve results from [Pulsedive](https://pulsedive.com/)'s API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "PULSEDIVE_API_KEY",
        "description": "Optional API key.",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "scan_mode": {
        "value": "basic",
        "type": "str",
        "description": "[basic, passive, active] By Default there is no scan of the observable. You can choose to add either active or passive scanning. See [doc](https://pulsedive.com/api/scan) for more info"
      }
    }
  },
  "Qiling_Windows": {
    "type": "file",
    "python_module": "qiling.Qiling",
    "description": "Qiling PE emulation",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "os": {
        "value": "windows",
        "type": "str",
        "description": "Change operating system for the emulation."
      },
      "arch": {
        "value": "x86",
        "type": "str",
        "description": "Change system architecture for the emulation."
      },
      "profile": {
        "value": "",
        "type": "str",
        "description": "Add a Qiling [profile](https://docs.qiling.io/en/latest/profile/)."
      },
      "shellcode": {
        "value": False,
        "type": "bool",
        "description": "true if the file is a shellcode."
      }
    }
  },
  "Qiling_Windows_Shellcode": {
    "type": "file",
    "python_module": "qiling.Qiling",
    "description": "Qiling windows shellcode emulation",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/octet-stream"],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "os": {
        "value": "windows",
        "type": "str",
        "description": "Change operating system for the emulation."
      },
      "arch": {
        "value": "x86",
        "type": "str",
        "description": "Change system architecture for the emulation."
      },
      "profile": {
        "value": "",
        "type": "str",
        "description": "Add a Qiling [profile](https://docs.qiling.io/en/latest/profile/)."
      },
      "shellcode": {
        "value": True,
        "type": "bool",
        "description": "true if the file is a shellcode."
      }
    }
  },
  "Qiling_Linux": {
    "type": "file",
    "python_module": "qiling.Qiling",
    "description": "Qiling ELF emulation",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": [
      "application/x-sharedlib",
      "application/x-executable",
      "application/x-elf"
    ],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "os": {
        "value": "linux",
        "type": "str",
        "description": "Change operating system for the emulation."
      },
      "arch": {
        "value": "x86",
        "type": "str",
        "description": "Change system architecture for the emulation."
      },
      "profile": {
        "value": "",
        "type": "str",
        "description": "Add a Qiling [profile](https://docs.qiling.io/en/latest/profile/)."
      },
      "shellcode": {
        "value": False,
        "type": "bool",
        "description": "true if the file is a shellcode."
      }
    }
  },
  "Qiling_Linux_Shellcode": {
    "type": "file",
    "python_module": "qiling.Qiling",
    "description": "Qiling linux shellcode emulation",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/octet-stream"],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "os": {
        "value": "linux",
        "type": "str",
        "description": "Change operating system for the emulation "
      },
      "arch": {
        "value": "x86",
        "type": "str",
        "description": "Change system architecture for the emulation."
      },
      "profile": {
        "value": "",
        "type": "str",
        "description": "Add a Qiling [profile](https://docs.qiling.io/en/latest/profile/)."
      },
      "shellcode": {
        "value": True,
        "type": "bool",
        "description": "true if the file is a shellcode."
      }
    }
  },
  "Quad9_DNS": {
    "type": "observable",
    "python_module": "dns.dns_resolvers.quad9_dns_resolver.Quad9DNSResolver",
    "description": "Retrieve current domain resolution with Quad9 DoH (DNS over HTTPS)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query_type": {
        "value": "A",
        "type": "str",
        "description": "Query type against the chosen DNS resolver."
      }
    }
  },
  "Quad9_Malicious_Detector": {
    "type": "observable",
    "python_module": "dns.dns_malicious_detectors.quad9_malicious_detector.Quad9MaliciousDetector",
    "description": "Check if a domain or an url is marked as malicious in Quad9 database",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Quark_Engine_APK": {
    "type": "file",
    "python_module": "quark_engine.QuarkEngine",
    "description": "An Obfuscation-Neglect Android Malware Scoring System",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/zip",
      "application/java-archive",
      "application/vnd.android.package-archive",
      "application/x-dex",
      "android"
    ],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {}
  },
  "Robtex": {
    "type": "observable",
    "python_module": "robtex.Robtex",
    "description": "scan a domain/IP against the Robtex Passive DNS DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url", "ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Rtf_Info": {
    "type": "file",
    "python_module": "rtf_info.RTFInfo",
    "description": "static RTF analysis (Oletools)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["text/rtf", "application/rtf"],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "Securitytrails": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against [securitytrails API](https://securitytrails.com/)",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "current",
        "type": "str",
        "description": "Analysis Type. Available options: current, history"
      },
      "securitytrails_current_type": {
        "value": "details",
        "type": "str",
        "description": "Suboptions if you chose 'current' analysis type. Options: details,subdomains,tags"
      },
      "securitytrails_history_type": {
        "value": "whois",
        "type": "str",
        "description": "Suboptions if you chose 'history' analysis type. Options: whois,dns"
      }
    }
  },
  "Securitytrails_Details": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against securitytrails API for general details",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "current",
        "type": "str",
        "description": ""
      },
      "securitytrails_current_type": {
        "value": "details",
        "type": "str",
        "description": ""
      }
    }
  },
  "Securitytrails_History_DNS": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against securitytrails API for historical DNS",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "history",
        "type": "str",
        "description": ""
      },
      "securitytrails_history_analysis": {
        "value": "dns",
        "type": "str",
        "description": ""
      }
    }
  },
  "Securitytrails_History_WHOIS": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against securitytrails API for historical WHOIS",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "history",
        "type": "str",
        "description": ""
      },
      "securitytrails_history_analysis": {
        "value": "whois",
        "type": "str",
        "description": ""
      }
    }
  },
  "Securitytrails_IP_Neighbours": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan an IP against securitytrails API for neighbour IPs",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Securitytrails_Subdomains": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against securitytrails API for subdomains",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "current",
        "type": "str",
        "description": ""
      },
      "securitytrails_current_type": {
        "value": "subdomains",
        "type": "str",
        "description": ""
      }
    }
  },
  "Securitytrails_Tags": {
    "type": "observable",
    "python_module": "securitytrails.SecurityTrails",
    "description": "scan a domain against securitytrails API for tags",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SECURITYTRAILS_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "securitytrails_analysis": {
        "value": "current",
        "type": "str",
        "description": ""
      },
      "securitytrails_current_type": {
        "value": "tags",
        "type": "str",
        "description": ""
      }
    }
  },
  "Shodan_Honeyscore": {
    "type": "observable",
    "python_module": "shodan.Shodan",
    "description": "scan an IP against Shodan Honeyscore API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SHODAN_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "shodan_analysis": {
        "value": "honeyscore",
        "type": "str",
        "description": ""
      }
    }
  },
  "Shodan_Search": {
    "type": "observable",
    "python_module": "shodan.Shodan",
    "description": "scan an IP against Shodan Search API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SHODAN_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "shodan_analysis": {
        "value": "search",
        "type": "str",
        "description": ""
      }
    }
  },
  "Signature_Info": {
    "type": "file",
    "python_module": "signature_info.SignatureInfo",
    "description": "PE signature extractor with [osslsigncode](https://github.com/mtrojnar/osslsigncode)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {}
  },
  "SpeakEasy": {
    "type": "file",
    "python_module": "speakeasy_emulation.SpeakEasy",
    "description": "SpeakEasy emulation report by Mandiant",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "arch": {
        "value": "x64",
        "type": "str",
        "description": "Change system architecture for the shellcode (x86 or x64)."
      },
      "shellcode": {
        "value": False,
        "type": "bool",
        "description": "true if the file is a shellcode."
      },
      "raw_offset": {
        "value": 0,
        "type": "int",
        "description": "Offset to start emulating."
      }
    }
  },
  "SpeakEasy_Shellcode": {
    "type": "file",
    "python_module": "speakeasy_emulation.SpeakEasy",
    "description": "SpeakEasy emulation shellcode report by Mandiant",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": ["application/octet-stream"],
    "config": {
      "soft_time_limit": 120,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "arch": {
        "value": "x64",
        "type": "str",
        "description": "Change system architecture for the shellcode (x86 or x64)."
      },
      "shellcode": {
        "value": True,
        "type": "bool",
        "description": "true if the file is a shellcode."
      },
      "raw_offset": {
        "value": 0,
        "type": "int",
        "description": "Offset to start emulating."
      }
    }
  },
  "Spyse": {
    "type": "observable",
    "python_module": "spyse.Spyse",
    "description": "Scan domains, IPs, emails and CVEs using Spyse.com's API. Register [here](https://spyse.com/user/registration).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SPYSE_API_KEY",
        "description": "Spyse API token",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "SSAPINet": {
    "type": "observable",
    "python_module": "ss_api_net.SSAPINet",
    "description": "Get a screenshot of a web page using screenshotapi.net. For configuration, Refer to the [docs](https://screenshotapi.net/documentation).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["url"],
    "config": {
      "soft_time_limit": 300,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "SSAPINET_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "use_proxy": {
        "value": False,
        "type": "bool",
        "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server."
      },
      "proxy": {
        "value": "",
        "type": "str",
        "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server."
      },
      "output": {
        "value": "image",
        "type": "str",
        "description": "Specify output type (options: `image` i.e. raw base64 encoded image, `json` i.e. containing link)"
      },
      "extra_api_params": {
        "value": {
          "full_page": True,
          "fresh": False,
          "lazy_load": False,
          "destroy_screenshot": False
        },
        "type": "dict",
        "description": "Refer to their docs](https://screenshotapi.net/documentation)."
      }
    }
  },
  "Stalkphish": {
    "type": "observable",
    "python_module": "stalkphish.Stalkphish",
    "description": "Check in url or ipv4 if string exists in [Stalkphish.io](https://www.stalkphish.io/) API.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["url", "ip", "domain", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "STALKPHISH_KEY",
        "description": "API key.",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "Strings_Info": {
    "type": "file",
    "python_module": "strings_info.StringsInfo",
    "description": "Strings extraction. Leverages Mandiant's [Stringsifter](https://github.com/mandiant/stringsifter)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "config": {
      "soft_time_limit": 70,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "max_number_of_strings": {
        "value": 500,
        "type": "int",
        "description": ""
      },
      "rank_strings": {
        "value": False,
        "type": "bool",
        "description": "enable ranking based on Machine Learning features"
      },
      "max_characters_for_string": {
        "value": 1000,
        "type": "int",
        "description": ""
      }
    }
  },
  "Strings_Info_Classic": {
    "type": "file",
    "python_module": "strings_info.StringsInfo",
    "description": "strings extraction [DEPRECATED, move to Strings_Info]",
    "disabled": True,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "config": {
      "soft_time_limit": 70,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "max_number_of_strings": {
        "value": 300,
        "type": "int",
        "description": ""
      },
      "rank_strings": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "max_characters_for_string": {
        "value": 1000,
        "type": "int",
        "description": ""
      }
    }
  },
  "Strings_Info_ML": {
    "type": "file",
    "python_module": "strings_info.StringsInfo",
    "description": "strings extraction plus strings ranking based on Machine Learning. Leverages Fireeye's Stringsifter [DEPRECATED, move to Strings_Info]",
    "disabled": True,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "config": {
      "soft_time_limit": 70,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "max_number_of_strings": {
        "value": 200,
        "type": "int",
        "description": ""
      },
      "rank_strings": {
        "value": True,
        "type": "bool",
        "description": ""
      },
      "max_characters_for_string": {
        "value": 1000,
        "type": "int",
        "description": ""
      }
    }
  },
  "Stratosphere_Blacklist": {
    "type": "observable",
    "python_module": "stratosphere.Stratos",
    "description": "Cross reference an IP in blacklist provided by Stratosphere lab",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 120,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Suricata": {
    "type": "file",
    "python_module": "suricata.Suricata",
    "description": "PCAP analysis with Suricata rules",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["application/vnd.tcpdump.pcap"],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "reload_rules": {
        "value": False,
        "type": "bool",
        "description": "Set this to true to force the reload of Rules. Useful in case you just added new custom rules and want to test them. By default the Rules are updated only once a day at UTC 00:00"
      },
      "extended_logs": {
        "value": False,
        "type": "bool",
        "description": "Set this to true to get all the raw logs generated by Suricata"
      }
    }
  },
  "TalosReputation": {
    "type": "observable",
    "python_module": "talos.Talos",
    "description": "check an IP reputation from Talos downloaded IP list",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "ThreatFox": {
    "type": "observable",
    "python_module": "threatfox.ThreatFox",
    "description": "search for an IOC in ThreatFox's database",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Threatminer": {
    "type": "observable",
    "python_module": "threatminer.Threatminer",
    "description": "retrieve data from [Threatminer API](https://www.threatminer.org/api.php)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "rt_value": {
        "value": 2,
        "type": "int",
        "description": "Request type. Default is PassiveDNS(rt=2). See [ThreatMiner APIs](https://www.threatminer.org/api.php) for more details about how to leverage this option"
      }
    }
  },
  "Threatminer_PDNS": {
    "type": "observable",
    "python_module": "threatminer.Threatminer",
    "description": "retrieve PDNS data from Threatminer API",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "rt_value": {
        "value": 2,
        "type": "int",
        "description": ""
      }
    }
  },
  "Threatminer_Reports_Tagging": {
    "type": "observable",
    "python_module": "threatminer.Threatminer",
    "description": "retrieve reports from Threatminer API",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "rt_value": {
        "value": 6,
        "type": "int",
        "description": ""
      }
    }
  },
  "Threatminer_Subdomains": {
    "type": "observable",
    "python_module": "threatminer.Threatminer",
    "description": "retrieve subdomains from Threatminer API",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "rt_value": {
        "value": 5,
        "type": "int",
        "description": ""
      }
    }
  },
  "Thug_HTML_Info": {
    "type": "file",
    "python_module": "thug_file.ThugFile",
    "description": "Perform hybrid dynamic/static analysis on a saved HTML page. For configuration, refer to [thug's usage docs](https://buffer.github.io/thug/doc/usage.html#basic-usage).",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "supported_filetypes": ["text/html"],
    "config": {
      "soft_time_limit": 600,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "dom_events": {
        "value": "click,mouseover",
        "type": "str",
        "description": "See [Thug docs: dom events handling](https://buffer.github.io/thug/doc/usage.html#dom-events-handling)."
      },
      "use_proxy": {
        "value": False,
        "type": "bool",
        "description": "option `-p`"
      },
      "proxy": {
        "value": "",
        "type": "str",
        "description": "option `-p`"
      },
      "enable_image_processing_analysis": {
        "value": True,
        "type": "bool",
        "description": "option `-a`"
      },
      "enable_awis": {
        "value": True,
        "type": "bool",
        "description": "option `-E`"
      },
      "user_agent": {
        "value": "winxpie60",
        "type": "str",
        "description": "See [Thug docs: browser personality](https://buffer.github.io/thug/doc/usage.html#browser-personality)."
      }
    }
  },
  "Thug_URL_Info": {
    "type": "observable",
    "python_module": "thug_url.ThugUrl",
    "description": "Perform hybrid dynamic/static analysis on a URL",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 600,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "dom_events": {
        "value": "click,mouseover",
        "type": "str",
        "description": "See [Thug docs: dom events handling](https://buffer.github.io/thug/doc/usage.html#dom-events-handling)."
      },
      "use_proxy": {
        "value": False,
        "type": "bool",
        "description": "option `-p`"
      },
      "proxy": {
        "value": "",
        "type": "str",
        "description": "option `-p`"
      },
      "enable_image_processing_analysis": {
        "value": True,
        "type": "bool",
        "description": "option `-a`"
      },
      "enable_awis": {
        "value": True,
        "type": "bool",
        "description": "option `-E`"
      },
      "user_agent": {
        "value": "winxpie60",
        "type": "str",
        "description": "See [Thug docs: browser personality](https://buffer.github.io/thug/doc/usage.html#browser-personality)."
      }
    }
  },
  "TorProject": {
    "type": "observable",
    "python_module": "tor.Tor",
    "description": "check if an IP is a Tor Exit Node",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Onionscan": {
    "type": "observable",
    "python_module": "onionscan.Onionscan",
    "description": "Scans TOR .onion domains for privacy leaks and information disclosures.",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "docker_based": True,
    "observable_supported": ["domain"],
    "config": {
      "soft_time_limit": 720,
      "queue": "long"
    },
    "secrets": {},
    "params": {
      "verbose": {
        "value": True,
        "type": "bool",
        "description": "Verbose output"
      },
      "tor_proxy_address": {
        "value": "",
        "type": "str",
        "description": "Tor proxy address"
      }
    }
  },
  "Tranco": {
    "type": "observable",
    "python_module": "tranco.Tranco",
    "description": "check if a domain is in the last Tranco ranking top sites list",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "Triage_Search": {
    "type": "observable",
    "python_module": "triage.triage_search.TriageSearch",
    "description": "lookup a file hash or an URL in Triage public sandbox Database",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash", "url"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "TRIAGE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "endpoint": {
        "value": "public",
        "type": "str",
        "description": "Choose whether to query on the public or the private endpoint of triage (options: `private`, `public`)."
      },
      "report_type": {
        "value": "overview",
        "type": "str",
        "description": "Determines how detailed the final report will be (options: `overview`, `complete`)."
      },
      "analysis_type": {
        "value": "search",
        "type": "str",
        "description": "Choose whether to search for existing observable reports or upload for scanning via URL (options: `search` and `submit`)."
      },
      "max_tries": {
        "value": 200,
        "type": "int",
        "description": ""
      }
    }
  },
  "Triage_Scan_URL": {
    "type": "observable",
    "python_module": "triage.triage_search.TriageSearch",
    "description": "analyze an URL using triage sandbox environment",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "observable_supported": ["url"],
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "TRIAGE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "endpoint": {
        "value": "public",
        "type": "str",
        "description": "Choose whether to query on the public or the private endpoint of triage (options: `private`, `public`)."
      },
      "report_type": {
        "value": "overview",
        "type": "str",
        "description": "Determines how detailed the final report will be (options: `overview`, `complete`)."
      },
      "analysis_type": {
        "value": "submit",
        "type": "str",
        "description": "Choose whether to search for existing observable reports or upload for scanning via URL (options: `search` and `submit`)."
      }
    }
  },
  "Triage_Scan": {
    "type": "file",
    "python_module": "triage_scan.TriageScanFile",
    "description": "leverage Triage sandbox environment to scan various files",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "TRIAGE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "endpoint": {
        "value": "public",
        "type": "str",
        "description": "Choose whether to query on the public or the private endpoint of triage (options: `private`, `public`)."
      },
      "report_type": {
        "value": "overview",
        "type": "str",
        "description": "Determines how detailed the final report will be (options: `overview`, `complete`)."
      },
      "max_tries":{
        "value": 200,
        "type": "int",
        "description": ""
      }
    }
  },
  "UnpacMe_EXE_Unpacker": {
    "type": "file",
    "python_module": "unpac_me.UnpacMe",
    "description": "UnpacMe unpacker",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "supported_filetypes": ["application/x-dosexec"],
    "config": {
      "soft_time_limit": 400,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "UNPAC_ME_API_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "private": {
        "value": False,
        "type": "bool",
        "description": ""
      },
      "max_tries": {
        "value": 30,
        "type": "int",
        "description": ""
      }
    }
  },
  "URLhaus": {
    "type": "observable",
    "python_module": "urlhaus.URLHaus",
    "description": "Query a domain or URL against URLhaus API",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["domain", "url", "ip"],
    "config": {
      "soft_time_limit": 50,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "UrlScan_Submit_Result": {
    "type": "observable",
    "python_module": "urlscan.UrlScan",
    "description": "Submit & retrieve result of a URL against [URLScan API](https://urlscan.io/docs/api/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["url"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "URLSCAN_API_KEY",
        "description": "API key is mandatory for submit.",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "visibility": {
        "value": "private",
        "type": "str",
        "description": ""
      },
      "urlscan_analysis": {
        "value": "submit_result",
        "type": "str",
        "description": ""
      },
      "search_size": {
        "value": 100,
        "type": "int",
        "description": ""
      }
    }
  },
  "UrlScan_Search": {
    "type": "observable",
    "python_module": "urlscan.UrlScan",
    "description": "Search an IP/domain/url/hash against [URLScan API](https://urlscan.io/docs/api/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 100,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "URLSCAN_API_KEY",
        "description": "API key is optional for search.",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "urlscan_analysis": {
        "value": "search",
        "type": "str",
        "description": ""
      },
      "search_size": {
        "value": 100,
        "type": "int",
        "description": ""
      }
    }
  },
  "Virushee_CheckHash": {
    "type": "observable",
    "python_module": "virushee.VirusheeCheckHash",
    "description": "Search for a previous analysis of a file by its hash (SHA256/SHA1/MD5) on [Virushee API](https://api.virushee.com/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["hash"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VIRUSHEE_API_KEY",
        "description": "[virushee docs](https://api.virushee.com/#section/Authentication)",
        "required": False,
        "type": "str"
      }
    },
    "params": {}
  },
  "Virushee_Upload_File": {
    "type": "file",
    "python_module": "virushee.VirusheeFileUpload",
    "description": "Check file hash and upload file sample for analysis on [Virushee API](https://api.virushee.com/).",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "config": {
      "soft_time_limit": 300,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VIRUSHEE_API_KEY",
        "description": "[virushee docs](https://api.virushee.com/#section/Authentication)",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "force_scan": {
        "value": False,
        "type": "bool",
        "description": "If True, always upload file for analysis skipping the hash check."
      }
    }
  },
  "VirusTotal_v2_Get_File": {
    "type": "file",
    "python_module": "vt.vt2_get.VirusTotalv2",
    "description": "check file hash on VirusTotal using old API endpoints",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "VirusTotal_v2_Get_Observable": {
    "type": "observable",
    "python_module": "vt.vt2_get.VirusTotalv2",
    "description": "search an observable in the VirusTotal DB using the old API endpoints",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "VirusTotal_v2_Scan_File": {
    "type": "file",
    "python_module": "vt.vt2_scan.VirusTotalv2ScanFile",
    "description": "scan a file on VirusTotal using old API endpoints",
    "disabled": True,
    "external_service": True,
    "leaks_info": True,
    "config": {
      "soft_time_limit": 400,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "VT_NOTIFY_URL",
        "description": "",
        "required": False,
        "type": "str",
        "default": ""
      }
    },
    "params": {}
  },
  "VirusTotal_v3_Get_File": {
    "type": "file",
    "python_module": "vt.vt3_get.VirusTotalv3",
    "description": "check file hash on VirusTotal",
    "disabled": True,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "run_hash_type": "sha256",
    "config": {
      "soft_time_limit": 800,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "max_tries": {
        "value": 10,
        "type": "int",
        "description": "How many times we poll the VT API for scan results"
      },
      "poll_distance": {
        "value": 30,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs"
      },
      "force_active_scan_if_old": {
        "value": False,
        "type": "bool",
        "description": "If the sample is old, it would be rescanned. This will cost additional quota."
      },
      "rescan_max_tries": {
        "value": 5,
        "type": "int",
        "description": "How many times we poll the VT API for RE-scan results (samples already available to VT)"
      },
      "rescan_poll_distance": {
        "value": 120,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan"
      },
      "days_to_say_that_a_scan_is_old": {
        "value": 30,
        "type": "int",
        "description": "How many days are required to consider a scan old to force rescan"
      },
      "include_behaviour_summary": {
        "value": False,
        "type": "bool",
        "description": "Include a summary of behavioral analysis reports alongside default scan report. This will cost additional quota."
      },
      "include_sigma_analyses": {
        "value": False,
        "type": "bool",
        "description": "Include sigma analysis report alongside default scan report. This will cost additional quota."
      },
      "relationships_to_request": {
        "value": [],
        "type": "list",
        "description": "Include a list of relationships to request if available. Full list [here](https://developers.virustotal.com/reference/metadata). This will cost additional quota."
      },
      "relationships_elements": {
        "value": 1,
        "type": "int",
        "description": "Number of elements to retrieve for each relationships"
      }
    }
  },
  "VirusTotal_v3_Get_File_And_Scan": {
    "type": "file",
    "python_module": "vt.vt3_get.VirusTotalv3",
    "description": "check file hash on VirusTotal. If not already available, send the sample and perform a new scan",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "run_hash": True,
    "run_hash_type": "sha256",
    "config": {
      "soft_time_limit": 800,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "max_tries": {
        "value": 10,
        "type": "int",
        "description": "How many times we poll the VT API for scan results"
      },
      "poll_distance": {
        "value": 30,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs"
      },
      "force_active_scan": {
        "value": True,
        "type": "bool",
        "description": "If the sample is not already in VT, send the sample and perform a scan"
      },
      "force_active_scan_if_old": {
        "value": True,
        "type": "bool",
        "description": "If the sample is old, it would be rescanned. This will cost additional quota."
      },
      "rescan_max_tries": {
        "value": 5,
        "type": "int",
        "description": "How many times we poll the VT API for RE-scan results (samples already available to VT)"
      },
      "rescan_poll_distance": {
        "value": 120,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan"
      },
      "days_to_say_that_a_scan_is_old": {
        "value": 30,
        "type": "int",
        "description": "How many days are required to consider a scan old to force rescan"
      },
      "include_behaviour_summary": {
        "value": True,
        "type": "bool",
        "description": "Include a summary of behavioral analysis reports alongside default scan report. This will cost additional quota."
      },
      "include_sigma_analyses": {
        "value": True,
        "type": "bool",
        "description": "Include sigma analysis report alongside default scan report. This will cost additional quota."
      },
      "relationships_to_request": {
        "value": [],
        "type": "list",
        "description": "Include a list of relationships to request if available. This will cost additional quota."
      },
      "relationships_elements": {
        "value": 1,
        "type": "int",
        "description": "Number of elements to retrieve for each relationships"
      }
    }
  },
  "VirusTotal_v3_Get_Observable": {
    "type": "observable",
    "python_module": "vt.vt3_get.VirusTotalv3",
    "description": "search an observable in the VirusTotal DB",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash"],
    "config": {
      "soft_time_limit": 800,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "max_tries": {
        "value": 10,
        "type": "int",
        "description": "How many times we poll the VT API for scan results"
      },
      "poll_distance": {
        "value": 30,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs"
      },
      "force_active_scan_if_old": {
        "value": False,
        "type": "bool",
        "description": "If you submitted an hash and the sample is old, it would be rescanned. This will cost additional quota."
      },
      "rescan_max_tries": {
        "value": 5,
        "type": "int",
        "description": "How many times we poll the VT API for RE-scan results (samples already available to VT)"
      },
      "rescan_poll_distance": {
        "value": 120,
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan"
      },
      "days_to_say_that_a_scan_is_old": {
        "value": 30,
        "type": "int",
        "description": "How many days are required to consider a scan old to force rescan"
      },
      "include_behaviour_summary": {
        "value": False,
        "type": "bool",
        "description": "If you submitted an hash, include a summary of behavioral analysis reports alongside default scan report. This will cost additional quota."
      },
      "include_sigma_analyses": {
        "value": False,
        "type": "bool",
        "description": "If you submitted an hash, include sigma analysis report alongside default scan report. This will cost additional quota."
      },
      "relationships_to_request": {
        "value": [],
        "type": "list",
        "description": "Include a list of relationships to request if available. This will cost additional quota."
      },
      "relationships_elements": {
        "value": 1,
        "type": "int",
        "description": "Number of elements to retrieve for each relationships"
      }
    }
  },
  "VirusTotal_v3_Intelligence_Search": {
    "type": "observable",
    "python_module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
    "description": "perform an advanced query through VirusTotal Intelligence. This is a premium feature only",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "VT_INTELLIGENCE_KEY",
        "required": True,
        "description": "API Key for the analyzer. You need to have a premium license with VT.",
        "type": "str"
      }
    },
    "params": {
      "limit": {
        "value": 300,
        "type": "int",
        "description": "max number of results to retrieve"
      }
    }
  },
  "Whoisxmlapi": {
    "type": "observable",
    "python_module": "whoisxmlapi.Whoisxmlapi",
    "description": "the WHOIS record data, of a domain name, an IP address, or an email address",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "WHOISXMLAPI_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {}
  },
  "WhoIs_RipeDB_Search": {
    "type": "observable",
    "python_module": "whoisripe.WhoIsRipeAPI",
    "description": "Fetch whois record data of an IP address from Ripe DB using their [search API](https://github.com/RIPE-NCC/whois/wiki/WHOIS-REST-API-search)",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {}
  },
  "WiGLE": {
    "type": "observable",
    "python_module": "wigle.WiGLE",
    "description": "Maps and database of 802.11 wireless networks, with statistics, submitted by wardrivers, netstumblers, and net huggers. Also, the string to be passed in input field of generic analyzers have a format. Different variables are separated by semicolons(`;`) and the field-name and value are separated by equals sign(`=`). Example string for search_type `CDMA Network` is `sid=12345;nid=12345;bsid=12345`.",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "WIGLE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "search_type": {
        "value": "WiFi Network",
        "type": "str",
        "description": "Corresponds to different routes mentioned in [docs](https://api.wigle.net/swagger#/v3_ALPHA). (options: `WiFi Network`, `CDMA Network`, `Bluetooth Network`, `GSM/LTE/WCDMA Network`)."
      }
    }
  },
  "XForceExchange": {
    "type": "observable",
    "python_module": "xforce.XForce",
    "description": "scan an observable on IBM X-Force Exchange",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "hash", "domain", "url"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "XFORCE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      },
      "api_password_name": {
        "env_var_key": "XFORCE_PASSWORD",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "malware_only": {
        "value": False,
        "type": "bool",
        "description": "Performs lookup only against 'malware' endpoints to save some quota"
      }
    }
  },
  "Xlm_Macro_Deobfuscator": {
    "type": "file",
    "python_module": "xlm_macro_deobfuscator.XlmMacroDeobfuscator",
    "description": "Extracting Office XLM Macros with [XlmMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator)",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "supported_filetypes": [
      "application/vnd.ms-excel.addin.macroEnabled",
      "application/x-mspublisher",
      "application/vnd.ms-excel",
      "application/vnd.ms-excel.sheet.macroEnabled.12",
      "application/excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/zip",
      "application/xml",
      "application/encrypted"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "local"
    },
    "secrets": {},
    "params": {
      "passwords_to_check": {
        "value": ["agenzia", "inps", "coronavirus"],
        "type": "list",
        "description": ""
      }
    }
  },
   "Yara": {
    "type": "file",
    "python_module": "yara_scan.YaraScan",
    "description": "scan a file with Yara rules",
    "disabled": False,
    "external_service": False,
    "leaks_info": False,
    "config": {
      "soft_time_limit": 120,
      "queue": "local"
    },
    "secrets": {
      "private_repositories": {
        "env_var_key": "YARA_PRIVATE_REPOSITORIES",
        "description": "Private repositories in the following format: {\"username@provider:org/repository.git\":\"ssh key\"}. Use double quote, don't worry about whitespace.",
        "required": False,
        "type": "dict",
        "default": {}
      }
    },
    "params": {
      "public_repositories": {
        "value": [
          "https://github.com/elastic/protections-artifacts",
          "https://github.com/embee-research/Yara",
          "https://github.com/JPCERTCC/jpcert-yara",
          "https://github.com/SIFalcon/Detection/",
          "https://github.com/bartblaze/Yara-rules",
          "https://github.com/intezer/yara-rules",
          "https://github.com/advanced-threat-research/Yara-Rules",
          "https://github.com/stratosphereips/yara-rules",
          "https://github.com/reversinglabs/reversinglabs-yara-rules",
          "https://github.com/sbousseaden/YaraHunts",
          "https://github.com/InQuest/yara-rules",
          "https://github.com/StrangerealIntel/DailyIOC",
          "https://github.com/mandiant/red_team_tool_countermeasures",
          "https://github.com/fboldewin/YARA-rules",
          "https://github.com/Yara-Rules/rules.git",
          "https://github.com/Neo23x0/signature-base.git",
          "https://yaraify-api.abuse.ch/download/yaraify-rules.zip"
        ],
        "type": "list",
        "description": "Repositories that will be constantly updated"
      },
      "local_rules": {
        "value": False,
        "type": "bool",
        "description": "If True, use local rules present at /opt/deploy/files_required/yara/YOUR_USER/custom_rule"
      },
     "ignore": {
        "value": [
          "generic_anomalies.yar",
          "general_cloaking.yar",
          "thor_inverse_matches.yar",
          "yara_mixed_ext_vars.yar",
          "thor-webshells.yar"
        ],
       "type": "list",
      "description": "ignore these rules"
      }
    }

  },
  "YARAify_File_Scan": {
    "type": "file",
    "python_module": "yaraify_file_scan.YARAifyFileScan",
    "description": "scan a file against public and non-public YARA and ClamAV signatures in YARAify service",
    "disabled": False,
    "external_service": True,
    "leaks_info": True,
    "supported_filetypes": [],
    "config": {
      "soft_time_limit": 500,
      "queue": "long"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MALPEDIA_TOKEN",
        "description": "Optional key to receive results from public (TLP:WHITE) and non-public (TLP:GREEN, TLP:AMBER and TLP:RED) YARA rules.",
        "required": True,
        "type": "str"
      },
      "api_key_identifier": {
        "env_var_key": "YARAIFY_KEY",
        "description": "Optional identifier to associate this submission with",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "send_file": {
        "value": True,
        "type": "bool",
        "description": "Defines whether the file should be sent for analysis or not (in the latter case hash only check would be done)"
      },
      "clamav_scan": {
        "value": True,
        "type": "bool",
        "description": "Defines whether to scan the file with ClamAV."
      },
      "unpack": {
        "value": False,
        "type": "bool",
        "description": "Defines whether to unpack the file."
      },
      "share_file": {
        "value": False,
        "type": "bool",
        "description": "Defines whether the file is public and may be shared with 3rd parties."
      },
      "skip_noisy": {
        "value": True,
        "type": "bool",
        "description": "YARAify skips the file if it already has been scanned at least 10 times within the past 24 hours. It will return the latest task_id instead"
      },
      "skip_known": {
        "value": False,
        "type": "bool",
        "description": "YARAify will not process the file if the file is already known."
      },
      "result_max": {
        "value": 25,
        "type": "int",
        "description": "Max number of results you want to display (default: 25, max: 1'000)"
      }
    }
  },
  "YARAify_Generics": {
    "type": "observable",
    "python_module": "yaraify.YARAify",
    "description": "lookup a YARA rule (default), ClamAV rule, imphash, TLSH, telfhash or icon_dash in YARAify",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": [
      "generic"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {},
    "params": {
      "query": {
        "value": "get_yara",
        "type": "str",
        "description": "using: 'get_yara' for YARA rule (default), 'get_clamav' for ClamAV signature, 'get_imphash' for imphash, 'get_tlsh' for TLSH, 'get_telfhash' for telfhash or 'get_dhash_icon' for icon_dash"
      },
      "result_max": {
        "value": 25,
        "type": "int",
        "description": "Max number of results you want to display (default: 25, max: 1'000)"
      }
    }
  },
  "YARAify_File_Search": {
    "type": "file",
    "python_module": "yaraify.YARAify",
    "description": "lookup a file hash in YARAify",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "run_hash": True,
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MALPEDIA_TOKEN",
        "description": "Optional key to receive results from public (TLP:WHITE) and also non-public (TLP:GREEN, TLP:AMBER and TLP:RED) YARA rules.",
        "required": False,
        "type": "str"
      }
    },
    "params": {}
  },
  "YARAify_Search": {
    "type": "observable",
    "python_module": "yaraify.YARAify",
    "description": "lookup a file hash in YARAify",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": [
      "hash"
    ],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "MALPEDIA_TOKEN",
        "description": "Optional key to receive results from public (TLP:WHITE) and also non-public (TLP:GREEN, TLP:AMBER and TLP:RED) YARA rules.",
        "required": False,
        "type": "str"
      }
    },
    "params": {
      "query": {
        "value": "lookup_hash",
        "type": "str",
        "description": ""
      }
    }
  },
  "YETI": {
    "type": "observable",
    "python_module": "yeti.YETI",
    "description": "scan an observable on a custom YETI instance",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain", "url", "hash", "generic"],
    "config": {
      "soft_time_limit": 30,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "YETI_KEY",
        "description": "API key for your YETI instance",
        "required": True,
        "type": "str"
      },
      "url_key_name": {
        "env_var_key": "YETI_URL",
        "description": "API URL of your YETI instance",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "verify_ssl": {
        "value": True,
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your YETI instance has not SSL enabled."
      },
      "regex": {
        "value": False,
        "type": "bool",
        "description": "Use this if you are searching for observables using a regex."
      },
      "results_count": {
        "value": 50,
        "type": "int",
        "description": "Use this to limit the maximum number of results obtained from a search."
      }
    }
  },
  "ZoomEye": {
    "type": "observable",
    "python_module": "zoomeye.ZoomEye",
    "description": "Cyberspace Search Engine recording information of devices, websites, services, components etc. [Host search: docs](https://www.zoomeye.org/doc#host-search).",
    "disabled": False,
    "external_service": True,
    "leaks_info": False,
    "observable_supported": ["ip", "domain"],
    "config": {
      "soft_time_limit": 60,
      "queue": "default"
    },
    "secrets": {
      "api_key_name": {
        "env_var_key": "ZOOMEYE_KEY",
        "description": "",
        "required": True,
        "type": "str"
      }
    },
    "params": {
      "search_type": {
        "value": "host",
        "type": "str",
        "description": "Choose among `host`, `web`, `both` (both is only available to ZoomEye VIP users)."
      },
      "query": {
        "value": "",
        "type": "str",
        "description": "Follow according to docs, but omit `ip`, `hostname`. Eg: `city:beijing port:21`."
      },
      "page": {
        "value": 1,
        "type": "int",
        "description": "Page number to fetch."
      },
      "facets": {
        "value": "",
        "type": "str",
        "description": "A comma-separated list of properties to get summary information on query. Eg: `facets:app,os`."
      },
      "history": {
        "value": True,
        "type": "bool",
        "description": "To query the history data."
      }
    }
  }
}

from django.db import migrations


def create_configurations(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for analyzer_name, analyzer in analyzers.items():
        for param in analyzer["params"].values():
            param["default"] = param.pop("value")

        for secret in analyzer.setdefault("secrets", {}).values():
            if "type" not in secret.keys():
                secret["type"] = "str"
            secret.pop("env_var_key")
        if "leaks_info" not in analyzer:
            analyzer["leaks_info"] = False

        ac = AnalyzerConfig(
            name=analyzer_name,
            **analyzer
        )
        ac.full_clean()
        ac.save()

def delete_configurations(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.all().delete()

class Migration(migrations.Migration):

    dependencies = [
        ('analyzers_manager', '0003_analyzerconfig'),
        ('api_app', '0010_custom_config_playbooks'),
    ]

    operations = [
        migrations.RunPython(
            create_configurations, delete_configurations
        ),
    ]
