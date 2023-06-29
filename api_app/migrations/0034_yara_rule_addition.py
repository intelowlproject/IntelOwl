from django.db import migrations


def migrate(apps, schema_editor):
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    pc = PluginConfig.objects.get(pk=232)
    pc.value = [
        "https://github.com/dr4k0nia/yara-rules",
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
        "https://github.com/Yara-Rules/rules.git",
        "https://github.com/Neo23x0/signature-base.git",
        "https://yaraify-api.abuse.ch/download/yaraify-rules.zip",
        "https://github.com/facebook/malware-detection",
        "https://github.com/edelucia/rules/tree/main/yara",
    ]
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    pc = PluginConfig.objects.get(pk=232)
    pc.value = [
        "https://github.com/dr4k0nia/yara-rules",
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
        "https://github.com/Yara-Rules/rules.git",
        "https://github.com/Neo23x0/signature-base.git",
        "https://yaraify-api.abuse.ch/download/yaraify-rules.zip",
        "https://github.com/facebook/malware-detection",
    ]
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):

    dependencies = [
        ("api_app", "0033_alter_parameter_unique_together"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
