from django.db import migrations

playbooks = {
    "FREE_TO_USE_ANALYZERS": {
        "analyzers": {
            "APKiD_Scan_APK_DEX_JAR": {},
            "BoxJS_Scan_JavaScript": {},
            "CRXcavator": {},
            "Capa_Info": {},
            "Capa_Info_Shellcode": {
                "arch": "64",
                "shellcode": True
            },
            "CheckDMARC": {},
            "ClamAV": {},
            "Classic_DNS": {
                "query_type": "A"
            },
            "CloudFlare_Malicious_Detector": {},
            "CryptoScamDB_CheckAPI": {},
            "CyberChef": {
                "output_type": "",
                "recipe_code": [],
                "recipe_name": "to decimal"
            },
            "Cymru_Hash_Registry_Get_File": {},
            "Cymru_Hash_Registry_Get_Observable": {},
            "DNStwist": {
                "mxcheck": True,
                "ssdeep": True,
                "tld": True,
                "tld_dict": "abused_tlds.dict"
            },
            "Darksearch_Query": {
                "pages": 10,
                "proxies": {}
            },
            "DNS0_EU_Malicious_Detector": {},
            "Doc_Info": {
                "additional_passwords_to_check": []
            },
            "ELF_Info": {},
            "FileScan_Search": {},
            "FileScan_Upload_File": {},
            "File_Info": {},
            "FireHol_IPList": {
                "list_names": [
                    "firehol_level1.netset"
                ]
            },
            "Floss": {
                "max_no_of_strings": {
                    "decoded_strings": 1000,
                    "stack_strings": 1000,
                    "static_strings": 1000
                },
                "rank_strings": {
                    "decoded_strings": False,
                    "stack_strings": False,
                    "static_strings": False
                }
            },
            "Google_DNS": {
                "query_type": "A"
            },
            "GreyNoiseAlpha": {
                "greynoise_api_version": "v1"
            },
            "HashLookupServer_Get_File": {
                "hashlookup_server": ""
            },
            "HashLookupServer_Get_Observable": {
                "hashlookup_server": ""
            },
            "IPApi" : {},
            "MalwareBazaar_Get_File": {},
            "MalwareBazaar_Get_Observable": {},
            "MalwareBazaar_Google_Observable": {},
            "Manalyze": {},
            "Mnemonic_PassiveDNS": {
                "cof_format": True,
                "limit": 1000
            },
            "Onionscan": {
                "torProxyAddress": "",
                "verbose": True
            },
            "PDF_Info": {},
            "PE_Info": {},
            "PEframe_Scan": {},
            "Phishstats": {},
            "Qiling_Linux": {
                "arch": "x86",
                "os": "linux",
                "profile": "",
                "shellcode": False
            },
            "Qiling_Linux_Shellcode": {
                "arch": "x86",
                "os": "linux",
                "profile": "",
                "shellcode": True
            },
            "Qiling_Windows": {
                "arch": "x86",
                "os": "windows",
                "profile": "",
                "shellcode": False
            },
            "Qiling_Windows_Shellcode": {
                "arch": "x86",
                "os": "windows",
                "profile": "",
                "shellcode": True
            },
            "Quad9_Malicious_Detector": {},
            "Quark_Engine_APK": {},
            "Robtex": {},
            "Rtf_Info": {},
            "Signature_Info": {},
            "SpeakEasy": {},
            "SpeakEasy_Shellcode": {
                "arch": "x64",
                "raw_offset": 0,
                "shellcode": True
            },
            "Stratosphere_Blacklist": {},
            "Strings_Info": {},
            "Suricata": {
                "extended_logs": False,
                "reload_rules": False
            },
            "TalosReputation": {},
            "ThreatFox": {},
            "Threatminer_PDNS": {},
            "Thug_HTML_Info": {
                "dom_events": "click,mouseover",
                "enable_awis": True,
                "enable_image_processing_analysis": True,
                "proxy": "",
                "use_proxy": False,
                "user_agent": "winxpie60"
            },
            "Thug_URL_Info": {
                "dom_events": "click,mouseover",
                "enable_awis": True,
                "enable_image_processing_analysis": True,
                "proxy": "",
                "use_proxy": False,
                "user_agent": "winxpie60"
            },
            "TorProject": {},
            "Tranco": {},
            "URLhaus": {},
            "WhoIs_RipeDB_Search": {},
            "Xlm_Macro_Deobfuscator": {
                "passwords_to_check": [
                    "agenzia",
                    "inps",
                    "coronavirus"
                ]
            },
            "YARAify_Generics": {
                "query": "get_yara",
                "result_max": 25
            },
            "Yara": {
                "repositories": [
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
                "ignore": [
                  "generic_anomalies.yar",
                  "general_cloaking.yar",
                  "thor_inverse_matches.yar",
                  "yara_mixed_ext_vars.yar",
                  "thor-webshells.yar"
                ]
            }
        },
        "connectors": {},
        "description": "A playbook containing all free to use analyzers.",
        "disabled": False,
        "supports": [
            "ip",
            "url",
            "domain",
            "generic",
            "hash",
            "file"
        ]
    }
}


def create_configurations(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    ConnectorConfig = apps.get_model("connectors_manager", "ConnectorConfig")

    for playbook_name, playbook in playbooks.items():
        analyzers = playbook.pop("analyzers")
        connectors = playbook.pop("connectors")
        playbook["type"] = playbook.pop("supports")
        analyzers_to_add = AnalyzerConfig.objects.filter(name__in=analyzers.keys())
        connectors_to_add = ConnectorConfig.objects.filter(name__in=connectors.keys())
        playbook["runtime_configuration"] ={
            "analyzers": analyzers,
            "connectors": connectors,
        }
        pc = PlaybookConfig(
            name=playbook_name,
            **playbook
        )
        pc.full_clean()
        pc.save()
        pc.analyzers.set(analyzers_to_add)
        pc.connectors.set(connectors_to_add)

def delete_configurations(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    PlaybookConfig.objects.all().delete()

class Migration(migrations.Migration):

    dependencies = [
        ('playbooks_manager', '0003_playbook'),
        ('analyzers_manager', '0004_datamigration'),
        ('connectors_manager', '0004_datamigration'),
    ]

    operations = [
        migrations.RunPython(
            create_configurations, delete_configurations
        ),
    ]
