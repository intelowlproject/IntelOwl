# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="dnstwist.DNStwist"):
        config.params = {
            "tld_dict": {
                "default": "",
                "type": "str",
                "description": "Dictionary to use with `tld` argument. Options: `common_tlds.dict/abused_tlds.dict`",
            },
            "language_dict": {
                "default": "",
                "type": "str",
                "description": "Dictionary to use with `dictionary` argument. Options: `english.dict/french.dict/polish.dict`",
            },
            "fuzzy_hash": {
                "default": "ssdeep",
                "type": "str",
                "description": "Fuzzy Hash to use to detect similarities. Options `ssdeep/tlsh`",
            },
            "fuzzy_hash_url": {
                "default": "",
                "type": "str",
                "description": "Override URL to fetch the original web page from",
            },
            "mxcheck": {
                "default": True,
                "type": "bool",
                "description": "Find suspicious mail servers and flag them with SPYING-MX string.",
            },
            "user_agent": {
                "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.34",
                "type": "str",
                "description": "User Agent used to connect to sites",
            },
            "nameservers": {
                "default": "",
                "type": "str",
                "description": "Alternative DNS servers to use. Add them separated by commas",
            },
        }
        config.full_clean()
        config.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(python_module="dnstwist.DNStwist"):
        config.params = {
            "tld": {
                "default": True,
                "type": "bool",
                "description": "Check for domains with different TLDs by supplying a dictionary file.",
            },
            "tld_dict": {
                "default": "abused_tlds.dict",
                "type": "str",
                "description": "Dictionary to use with `tld` argument (`common_tlds.dict/abused_tlds.dict`).",
            },
            "mxcheck": {
                "default": True,
                "type": "bool",
                "description": "Find suspicious mail servers and flag them with SPYING-MX string.",
            },
            "ssdeep": {
                "default": True,
                "type": "bool",
                "description": "Enable fuzzy hashing - compare HTML content of original domain with a potentially "
                "malicious one and determine similarity.",
            },
        }
        config.full_clean()
        config.save()


class Migration(migrations.Migration):

    dependencies = [
        (
            "analyzers_manager",
            "0016_alter_analyzerconfig_not_supported_filetypes_and_more",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
