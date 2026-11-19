# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from importlib import import_module

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django_celery_beat.models import PeriodicTask
from kombu import uuid
from rest_framework.test import APIClient

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.models import Job, OrganizationPluginConfiguration, Parameter, PluginConfig, PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase

migration = import_module("api_app.analyzers_manager.migrations.0205_remove_spyse_crxcavator_analyzers")


class RemoveSpyseCRXcavatorMigrationTestCase(CustomTestCase):
    def test_analyzers_absent_after_migrations(self):
        self.assertFalse(AnalyzerConfig.objects.filter(name__in=["Spyse", "CRXcavator"]).exists())
        self.assertFalse(
            PythonModule.objects.filter(
                module__in=migration.REMOVED_MODULES,
                base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
            ).exists()
        )
        free_to_use = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
        self.assertFalse(free_to_use.analyzers.filter(name="CRXcavator").exists())

    def test_existing_jobs_survive(self):
        apps = MigrationLoader(connection).project_state().apps
        crontab = apps.get_model("django_celery_beat", "CrontabSchedule").objects.create(minute="0", hour="0")
        historical_task = apps.get_model("django_celery_beat", "PeriodicTask")
        update_task = historical_task.objects.create(
            name="CRXcavatorTestUpdate", task="intel_owl.tasks.update", crontab=crontab
        )
        health_task = historical_task.objects.create(
            name="CRXcavatorTestHealthCheck", task="intel_owl.tasks.health_check", crontab=crontab
        )
        pm = apps.get_model("api_app", "PythonModule").objects.create(
            module="crxcavator.CRXcavator",
            base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
            update_task=update_task,
        )
        historical_config = apps.get_model("analyzers_manager", "AnalyzerConfig").objects.create(
            name="CRXcavator",
            python_module=pm,
            description="test",
            disabled=False,
            type="observable",
            observable_supported=["generic"],
            run_hash=False,
            health_check_task=health_task,
        )
        apps.get_model("playbooks_manager", "PlaybookConfig").objects.get(
            name="FREE_TO_USE_ANALYZERS"
        ).analyzers.add(historical_config)

        removed_config = AnalyzerConfig.objects.get(pk=historical_config.pk)
        kept_config = AnalyzerConfig.objects.get(name="Classic_DNS")
        analyzable = Analyzable.objects.create(name="test.com", classification=Classification.GENERIC)
        job = Job.objects.create(
            analyzable=analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.analyzers_requested.set([removed_config, kept_config])
        job.analyzers_to_execute.set([removed_config, kept_config])
        for config in (removed_config, kept_config):
            AnalyzerReport.objects.create(
                report={},
                job=job,
                config=config,
                status=AnalyzerReport.STATUSES.SUCCESS.value,
                task_id=str(uuid()),
                parameters={},
            )

        migration.migrate(apps, None)

        self.assertTrue(Job.objects.filter(pk=job.pk).exists())
        self.assertEqual(
            list(AnalyzerReport.objects.filter(job=job).values_list("config__name", flat=True)),
            ["Classic_DNS"],
        )
        self.assertEqual(list(job.analyzers_requested.values_list("name", flat=True)), ["Classic_DNS"])
        self.assertEqual(list(job.analyzers_to_execute.values_list("name", flat=True)), ["Classic_DNS"])
        self.assertFalse(AnalyzerConfig.objects.filter(name="CRXcavator").exists())
        self.assertFalse(PythonModule.objects.filter(pk=pm.pk).exists())
        self.assertFalse(PeriodicTask.objects.filter(pk__in=[update_task.pk, health_task.pk]).exists())
        free_to_use = PlaybookConfig.objects.get(name="FREE_TO_USE_ANALYZERS")
        self.assertFalse(free_to_use.analyzers.filter(name="CRXcavator").exists())
        self.assertTrue(free_to_use.analyzers.filter(name="Classic_DNS").exists())

    def test_secrets_and_org_configurations_removed(self):
        apps = MigrationLoader(connection).project_state().apps
        historical_module = apps.get_model("api_app", "PythonModule")
        historical_config = apps.get_model("analyzers_manager", "AnalyzerConfig")
        pm = historical_module.objects.create(
            module="spyse.Spyse",
            base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
        )
        spyse = historical_config.objects.create(
            name="Spyse",
            python_module=pm,
            description="test",
            disabled=False,
            type="observable",
            observable_supported=["domain"],
            run_hash=False,
        )
        parameter = apps.get_model("api_app", "Parameter").objects.create(
            name="api_key_name",
            type="str",
            description="test",
            is_secret=True,
            required=True,
            python_module=pm,
        )
        value = apps.get_model("api_app", "PluginConfig").objects.create(
            parameter=parameter,
            value="secret",
            owner_id=self.user.pk,
            for_organization=False,
            analyzer_config=spyse,
        )
        crontab = apps.get_model("django_celery_beat", "CrontabSchedule").objects.create(minute="0", hour="0")
        rate_limit_task = apps.get_model("django_celery_beat", "PeriodicTask").objects.create(
            name="SpyseTestRateLimitCleaner",
            task="enable_configuration_for_org_for_rate_limit",
            crontab=crontab,
        )
        org = Organization.create("test_org", self.user)
        org_configuration = OrganizationPluginConfiguration.objects.create(
            content_type=ContentType.objects.get_for_model(AnalyzerConfig),
            object_id=spyse.pk,
            organization=org,
            disabled=True,
            rate_limit_enable_task_id=rate_limit_task.pk,
        )

        migration.migrate(apps, None)

        self.assertFalse(Parameter.objects.filter(pk=parameter.pk).exists())
        self.assertFalse(PluginConfig.objects.filter(pk=value.pk).exists())
        self.assertFalse(OrganizationPluginConfiguration.objects.filter(pk=org_configuration.pk).exists())
        self.assertFalse(PeriodicTask.objects.filter(pk=rate_limit_task.pk).exists())
        client = APIClient()
        client.force_authenticate(self.user)
        self.assertEqual(client.get("/api/plugin-disable/").status_code, 200)
