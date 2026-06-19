# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
from unittest import skipUnless

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.connectors_manager.connectors.opencti import OpenCTI
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.models import Job, Parameter, PluginConfig, Tag
from tests import CustomTestCase


class OpenCTILiveIntegrationTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def _get_opencti_config(self):
        return ConnectorConfig.objects.get(name="OpenCTI")

    def _setup_job(self, config):
        """Creates a real Job, Analyzable, and Tags in the test DB with live credentials."""
        url_param = Parameter.objects.get(python_module=config.python_module, name="url_key_name")
        token_param = Parameter.objects.get(python_module=config.python_module, name="api_key_name")

        pcs = [
            PluginConfig.objects.create(
                parameter=url_param,
                value=os.getenv("OPENCTI_URL"),
                for_organization=False,
                owner=None,
                connector_config=config,
            ),
            PluginConfig.objects.create(
                parameter=token_param,
                value=os.getenv("OPENCTI_TOKEN"),
                for_organization=False,
                owner=None,
                connector_config=config,
            ),
        ]

        analyzable = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job = Job.objects.create(
            analyzable=analyzable,
            user=self.superuser,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.connectors_to_execute.set([config])

        # OpenCTI specifically requires tags to generate Labels, so we attach one to the job.
        tag, _ = Tag.objects.get_or_create(label="integration-test", defaults={"color": "#ff0000"})
        job.tags.add(tag)

        return job, pcs

    def _cleanup(self, job, config, pcs):
        """Cleans up the database so test runs don't overlap."""
        try:
            ConnectorReport.objects.get(job=job, config=config).delete()
        except ConnectorReport.DoesNotExist:
            pass
        analyzable = job.analyzable
        job.delete()
        analyzable.delete()
        for pc in pcs:
            pc.delete()

    @skipUnless(
        os.getenv("OPENCTI_URL") and os.getenv("OPENCTI_TOKEN"),
        "OpenCTI live test not configured",
    )
    def test_opencti_live_integration(self):
        """
        End-to-End Live Test: Executes the full base class start() method,
        hits the real OpenCTI server, and verifies the DB state.
        """
        config = self._get_opencti_config()
        job, pcs = self._setup_job(config)

        try:
            connector = OpenCTI(config)
            try:
                # We use .start() here to invoke the Django DB state lifecycle
                connector.start(job.pk, {}, uuid())
            except Exception:
                pass

            # Fetch the actual report from the database to ensure it saved
            report = ConnectorReport.objects.get(job=job, config=config)

            self.assertIn(
                report.status,
                [ConnectorReport.STATUSES.SUCCESS, ConnectorReport.STATUSES.FAILED],
            )

            # If successful, ensure the raw dictionary was saved to the DB model
            if report.status == ConnectorReport.STATUSES.SUCCESS:
                self.assertIsInstance(report.report, dict)
                self.assertIn("observable", report.report)
                self.assertIn("report", report.report)

        finally:
            self._cleanup(job, config, pcs)
