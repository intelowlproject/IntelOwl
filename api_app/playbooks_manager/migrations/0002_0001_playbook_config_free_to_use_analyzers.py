from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "FREE_TO_USE_ANALYZERS",
    "analyzers": [
        "APKiD",
        "BoxJS",
        "CRXcavator",
        "Capa_Info",
        "Capa_Info_Shellcode",
        "CheckDMARC",
        "ClamAV",
        "Classic_DNS",
        "CloudFlare_DNS",
        "CloudFlare_Malicious_Detector",
        "CyberChef",
        "Cymru_Hash_Registry_Get_File",
        "Cymru_Hash_Registry_Get_Observable",
        "DNS0_EU",
        "DNS0_EU_Malicious_Detector",
        "DNS0_names",
        "DNS0_rrsets_name",
        "DNStwist",
        "Doc_Info",
        "ELF_Info",
        "FileScan_Search",
        "FileScan_Upload_File",
        "File_Info",
        "FireHol_IPList",
        "Floss",
        "Google_DNS",
        "HashLookupServer_Get_File",
        "HashLookupServer_Get_Observable",
        "IPApi",
        "MalwareBazaar_Get_File",
        "MalwareBazaar_Get_Observable",
        "MalwareBazaar_Google_Observable",
        "Mnemonic_PassiveDNS",
        "Onionscan",
        "PDF_Info",
        "PE_Info",
        "PEframe_Scan",
        "Phishstats",
        "Qiling_Linux",
        "Qiling_Linux_Shellcode",
        "Qiling_Windows",
        "Qiling_Windows_Shellcode",
        "Quad9_DNS",
        "Quad9_Malicious_Detector",
        "Quark_Engine",
        "Robtex",
        "Rtf_Info",
        "Signature_Info",
        "SpeakEasy",
        "SpeakEasy_Shellcode",
        "Stratosphere_Blacklist",
        "Strings_Info",
        "Suricata",
        "TalosReputation",
        "ThreatFox",
        "Thug_HTML_Info",
        "Thug_URL_Info",
        "TorProject",
        "Tranco",
        "URLhaus",
        "WhoIs_RipeDB_Search",
        "Xlm_Macro_Deobfuscator",
        "YARAify_Generics",
        "Yara",
    ],
    "connectors": [],
    "pivots": [],
    "for_organization": False,
    "description": "A playbook containing all free to use analyzers.",
    "disabled": False,
    "type": ["ip", "url", "domain", "generic", "hash", "file"],
    "runtime_configuration": {
        "analyzers": {
            "Yara": {
                "ignore": [
                    "generic_anomalies.yar",
                    "general_cloaking.yar",
                    "thor_inverse_matches.yar",
                    "yara_mixed_ext_vars.yar",
                    "thor-webshells.yar",
                ],
                "repositories": [
                    "https://github.com/elastic/protections-artifacts",
                    "https://github.com/embee-research/Yara",
                    "https://github.com/elceef/yara-rulz",
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
                    "https://github.com/dr4k0nia/yara-rules",
                    "https://github.com/Yara-Rules/rules.git",
                    "https://github.com/Neo23x0/signature-base.git",
                    "https://yaraify-api.abuse.ch/download/yaraify-rules.zip",
                ],
            },
            "APKiD": {},
            "Floss": {
                "rank_strings": {
                    "stack_strings": False,
                    "static_strings": False,
                    "decoded_strings": False,
                },
                "max_no_of_strings": {
                    "stack_strings": 1000,
                    "static_strings": 1000,
                    "decoded_strings": 1000,
                },
            },
            "IPApi": {},
            "ClamAV": {},
            "Robtex": {},
            "Tranco": {},
            "PE_Info": {},
            "URLhaus": {},
            "DNStwist": {
                "tld": True,
                "ssdeep": True,
                "mxcheck": True,
                "tld_dict": "abused_tlds.dict",
            },
            "Doc_Info": {"additional_passwords_to_check": []},
            "ELF_Info": {},
            "PDF_Info": {},
            "Rtf_Info": {},
            "Suricata": {"reload_rules": False, "extended_logs": False},
            "Capa_Info": {},
            "CyberChef": {
                "output_type": "",
                "recipe_code": [],
                "recipe_name": "to decimal",
            },
            "File_Info": {},
            "Onionscan": {"verbose": True, "torProxyAddress": ""},
            "SpeakEasy": {},
            "ThreatFox": {},
            "CRXcavator": {},
            "CheckDMARC": {},
            "Google_DNS": {"query_type": "A"},
            "Phishstats": {},
            "TorProject": {},
            "Classic_DNS": {"query_type": "A"},
            "PEframe_Scan": {},
            "Qiling_Linux": {
                "os": "linux",
                "arch": "x86",
                "profile": "",
                "shellcode": False,
            },
            "Quark_Engine": {},
            "Strings_Info": {},
            "Thug_URL_Info": {
                "proxy": "",
                "use_proxy": False,
                "dom_events": "click,mouseover",
                "user_agent": "winxpie60",
                "enable_awis": True,
                "enable_image_processing_analysis": True,
            },
            "FireHol_IPList": {"list_names": ["firehol_level1.netset"]},
            "GreyNoiseAlpha": {"greynoise_api_version": "v1"},
            "Qiling_Windows": {
                "os": "windows",
                "arch": "x86",
                "profile": "",
                "shellcode": False,
            },
            "Signature_Info": {},
            "Thug_HTML_Info": {
                "proxy": "",
                "use_proxy": False,
                "dom_events": "click,mouseover",
                "user_agent": "winxpie60",
                "enable_awis": True,
                "enable_image_processing_analysis": True,
            },
            "FileScan_Search": {},
            "TalosReputation": {},
            "Darksearch_Query": {"pages": 10, "proxies": {}},
            "Threatminer_PDNS": {},
            "YARAify_Generics": {"query": "get_yara", "result_max": 25},
            "Capa_Info_Shellcode": {"arch": "64", "shellcode": True},
            "Mnemonic_PassiveDNS": {"limit": 1000, "cof_format": True},
            "SpeakEasy_Shellcode": {"arch": "x64", "shellcode": True, "raw_offset": 0},
            "WhoIs_RipeDB_Search": {},
            "FileScan_Upload_File": {},
            "BoxJS_Scan_JavaScript": {},
            "CryptoScamDB_CheckAPI": {},
            "MalwareBazaar_Get_File": {},
            "Qiling_Linux_Shellcode": {
                "os": "linux",
                "arch": "x86",
                "profile": "",
                "shellcode": True,
            },
            "Stratosphere_Blacklist": {},
            "Xlm_Macro_Deobfuscator": {
                "passwords_to_check": ["agenzia", "inps", "coronavirus"]
            },
            "Qiling_Windows_Shellcode": {
                "os": "windows",
                "arch": "x86",
                "profile": "",
                "shellcode": True,
            },
            "Quad9_Malicious_Detector": {},
            "HashLookupServer_Get_File": {"hashlookup_server": ""},
            "DNS0_EU_Malicious_Detector": {},
            "Cymru_Hash_Registry_Get_File": {},
            "MalwareBazaar_Get_Observable": {},
            "CloudFlare_Malicious_Detector": {},
            "HashLookupServer_Get_Observable": {"hashlookup_server": ""},
            "MalwareBazaar_Google_Observable": {},
            "Cymru_Hash_Registry_Get_Observable": {},
        },
        "connectors": {},
        "visualizers": {},
    },
    "scan_mode": 2,
    "scan_check_time": "1 00:00:00",
    "tlp": "CLEAR",
    "owner": None,
    "disabled_in_organizations": [],
    "tags": [],
    "model": "playbooks_manager.PlaybookConfig",
}

params = []

values = []


def _get_real_obj(Model, field, value):
    if (
        type(getattr(Model, field))
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        # in case is a dictionary, we have to retrieve the object with every key
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            value = other_model.objects.get(pk=value)
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            value = _get_real_obj(Model, field, value)
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)
        return False
    return True


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    if not Model.objects.filter(name=plugin["name"]).exists():
        exists = _create_object(Model, plugin)
        if not exists:
            for param in params:
                _create_object(Parameter, param)
            for value in values:
                _create_object(PluginConfig, value)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0001_2_initial_squashed"),
        ("playbooks_manager", "0002_0000_playbook_config_dns"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
