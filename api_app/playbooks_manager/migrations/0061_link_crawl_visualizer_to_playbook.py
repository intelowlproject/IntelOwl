# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def link_visualizer(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    
    try:
        playbook = PlaybookConfig.objects.get(name="URL_Infrastructure_Scan")
        visualizer = VisualizerConfig.objects.get(name="Crawl_Results")
        
        playbook.visualizers.add(visualizer)
        playbook.full_clean()
        playbook.save()
        
        visualizer.playbooks.add(playbook)
        visualizer.full_clean()
        visualizer.save()
    except (PlaybookConfig.DoesNotExist, VisualizerConfig.DoesNotExist) as e:
        print(f"Skipping linking: {e}")


def unlink_visualizer(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    
    try:
        playbook = PlaybookConfig.objects.get(name="URL_Infrastructure_Scan")
        visualizer = VisualizerConfig.objects.get(name="Crawl_Results")
        
        playbook.visualizers.remove(visualizer)
        playbook.save()
        
        visualizer.playbooks.remove(playbook)
        visualizer.save()
    except (PlaybookConfig.DoesNotExist, VisualizerConfig.DoesNotExist):
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0060_playbook_config_url_infrastructure_scan"),
        ("visualizers_manager", "0041_visualizer_config_crawl_results"),
    ]

    operations = [migrations.RunPython(link_visualizer, unlink_visualizer)]
