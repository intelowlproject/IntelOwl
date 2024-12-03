from django.db import migrations

def add_yaraforge_analyzer(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    
    if not AnalyzerConfig.objects.filter(name="Yara-forge").exists():
        AnalyzerConfig.objects.create(
            name="Yara-forge",
            python_module="yaraforge",
            description="Analyzer that uses Yara-forge rules to scan files",
            routing_key="local",
            soft_time_limit=300,
            type="file",
            docker_based=True,
            maximum_tlp="WHITE",
            supported_filetypes=["application/x-dosexec", "*"],
            run_hash=False
        )

def remove_yaraforge_analyzer(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="Yara-forge").delete()

class Migration(migrations.Migration):
    dependencies = [
        ('analyzers_manager', '0025_your_previous_migration'),
    ]

    operations = [
        migrations.RunPython(add_yaraforge_analyzer, remove_yaraforge_analyzer),
    ]
