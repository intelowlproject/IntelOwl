from django.db import migrations

from api_app.choices import TLP


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="bgp_ranking.BGPRanking",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.AMBER
        analyzer.save()

    pm = PythonModule.objects.get(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.RED
        analyzer.save()

    pm = PythonModule.objects.get(
        module="mmdb_server.MmdbServer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.AMBER
        analyzer.save()

    pm = PythonModule.objects.get(
        module="phoneinfoga_scan.Phoneinfoga",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.AMBER
        analyzer.save()

    pm = PythonModule.objects.get(
        module="tweetfeeds.TweetFeeds",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.RED
        analyzer.save()

    pm = PythonModule.objects.get(
        module="validin.Validin",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.AMBER
        analyzer.save()

    pm = PythonModule.objects.get(
        module="zippy_scan.ZippyAnalyser",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.RED
        analyzer.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    pm = PythonModule.objects.get(
        module="bgp_ranking.BGPRanking",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="feodo_tracker.Feodo_Tracker",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="mmdb_server.MmdbServer",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="phoneinfoga_scan.Phoneinfoga",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="tweetfeeds.TweetFeeds",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="validin.Validin",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()

    pm = PythonModule.objects.get(
        module="zippy_scan.ZippyAnalyser",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    for analyzer in pm.analyzerconfigs.all():
        analyzer.maximum_tlp = TLP.CLEAR
        analyzer.save()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0073_remove_dragonfly_analyzer"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
