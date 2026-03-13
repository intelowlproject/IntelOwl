# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
from unittest import skipUnless
from unittest.mock import patch

import pytest
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.connectors_manager.connectors.opencti import OpenCTI
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.models import Job, Parameter, PluginConfig, Tag
from tests import CustomTestCase


# Connector uses pycti.Identity(inst).create(...), i.e. class(instance).method().
# Tests patch the pycti classes so instance calls are reliably intercepted.
def _partial_state_errors(report):
    """Errors that contain the partial-state contract message."""
    return [e for e in report.errors if "Created IDs:" in str(e)]


class OpenCTIConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def _get_opencti_config():
        return ConnectorConfig.objects.get(name="OpenCTI")

    @staticmethod
    def _create_plugin_configs(config):
        """Create required PluginConfig for OpenCTI (url_key_name, api_key_name)."""
        pcs = []
        for name in ("url_key_name", "api_key_name"):
            param = Parameter.objects.get(
                python_module=config.python_module,
                name=name,
            )
            pc = PluginConfig.objects.create(
                parameter=param,
                value="https://opencti.test" if "url" in name else "test-token",
                for_organization=False,
                owner=None,
                connector_config=config,
            )
            pcs.append(pc)
        return pcs

    def _setup_job_with_opencti(self, add_tag=True):
        """Create Analyzable, Job, attach OpenCTI config, optional tag. Returns (job, config, pcs)."""
        config = self._get_opencti_config()
        pcs = self._create_plugin_configs(config)

        analyzable = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        job = Job.objects.create(
            analyzable=analyzable,
            user=self.superuser,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.connectors_to_execute.set([config])
        if add_tag:
            tag, _ = Tag.objects.get_or_create(
                label="testtag",
                defaults={"color": "#ff0000"},
            )
            job.tags.add(tag)

        return job, config, pcs

    @staticmethod
    def _cleanup_test_objects(job, config, pcs):
        """Delete only objects created by this test (report for job+config, job, analyzable, pcs)."""
        try:
            report = ConnectorReport.objects.get(job=job, config=config)
            report.delete()
        except ConnectorReport.DoesNotExist:
            pass
        analyzable = job.analyzable
        job.delete()
        analyzable.delete()
        for pc in pcs:
            pc.delete()

    def _assert_no_traceback_in_errors(self, report):
        for err in report.errors:
            self.assertNotIn("Traceback", str(err))
            self.assertNotIn("File ", str(err))

    def tearDown(self):
        super().tearDown()

    @pytest.mark.parametrize(
        "scenario,expected_substrings,fail_target",
        [
            (
                "failure_after_observable_creation",
                ["observable=obs-1", "labels=[]"],
                "label",
            ),
            (
                "failure_after_report_creation",
                ["observable=obs-1", "report=report-1", "label-1"],
                "external_ref",
            ),
            (
                "failure_after_external_reference_before_linking",
                ["external_reference=ext-ref-1", "report=report-1", "observable=obs-1"],
                "link",
            ),
        ],
    )
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.StixDomainObject")
    @patch("pycti.ExternalReference")
    @patch("pycti.Report")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_partial_state_failure_scenarios(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        report_mock,
        external_ref_mock,
        stix_domain_mock,
        _api_client_mock,
        scenario,
        expected_substrings,
        fail_target,
    ):
        """
        Exercise the multi-step OpenCTI flow under different failure points while
        asserting that partial state is surfaced consistently in ConnectorReport.
        """
        # Common happy-path defaults
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.return_value = {"id": "ext-ref-1"}
        stix_domain_mock.return_value.add_external_reference.return_value = None

        # Force the failure point for this scenario.
        if fail_target == "label":
            label_mock.return_value.create.side_effect = Exception("label failure")
        elif fail_target == "external_ref":
            external_ref_mock.return_value.create.side_effect = Exception("external ref failure")
        elif fail_target == "link":
            stix_domain_mock.return_value.add_external_reference.side_effect = Exception("link failure")
        else:
            pytest.fail(f"Unknown fail_target {fail_target} for scenario {scenario}")

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            task_id = uuid()
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, task_id)
            except Exception:
                # In CI after_run_failed may re-raise; the ConnectorReport is still written.
                pass

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.FAILED)

            partial_msgs = _partial_state_errors(report)
            self.assertEqual(len(partial_msgs), 1)
            self.assertEqual(len(report.errors), 2)

            err_text = " ".join(map(str, report.errors))
            for substr in expected_substrings:
                self.assertIn(substr, err_text)

            # Contract: partial-state message is present and errors do not expose tracebacks.
            self._assert_no_traceback_in_errors(report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 4: Success path integrity ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.Report")
    @patch("pycti.StixDomainObject")
    @patch("pycti.ExternalReference")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_success_path_integrity(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        external_ref_mock,
        stix_domain_mock,
        report_mock,
        _api_client_mock,
    ):
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        stix_observable_mock.return_value.read.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        report_mock.return_value.read.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.return_value = {"id": "ext-1"}
        stix_domain_mock.return_value.add_external_reference.return_value = None
        report_mock.return_value.add_stix_object_or_stix_relationship.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            task_id = uuid()
            connector = OpenCTI(config)
            connector.start(job.pk, {}, task_id)

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.SUCCESS)
            self.assertEqual(report.errors, [])
            self.assertIsInstance(report.report, dict)
            self.assertIn("observable", report.report)
            self.assertIn("report", report.report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 5: Organization and marking called only once ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.Report")
    @patch("pycti.StixDomainObject")
    @patch("pycti.ExternalReference")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_organization_and_marking_called_only_once(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        external_ref_mock,
        stix_domain_mock,
        report_mock,
        _api_client_mock,
    ):
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        stix_observable_mock.return_value.read.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        report_mock.return_value.read.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.return_value = {"id": "ext-1"}
        stix_domain_mock.return_value.add_external_reference.return_value = None
        report_mock.return_value.add_stix_object_or_stix_relationship.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            task_id = uuid()
            connector = OpenCTI(config)
            connector.start(job.pk, {}, task_id)

            identity_mock.return_value.create.assert_called_once()
            marking_mock.return_value.create.assert_called_once()
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 6: API schema drift — StixCyberObservable.create returns non-dict ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.StixDomainObject")
    @patch("pycti.ExternalReference")
    @patch("pycti.Report")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_observable_create_returns_non_dict_handled_safely(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        report_mock,
        external_ref_mock,
        stix_domain_mock,
        _api_client_mock,
    ):
        """StixCyberObservable.create returns non-dict → connector records observable=None, fails safely."""
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = None
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.return_value = {"id": "ext-1"}
        stix_domain_mock.return_value.add_external_reference.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            task_id = uuid()
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, task_id)
            except Exception:
                pass  # In CI, after_run_failed re-raises; report is already FAILED

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.FAILED)

            partial_msgs = _partial_state_errors(report)
            self.assertEqual(len(partial_msgs), 1)
            self.assertEqual(len(report.errors), 2)
            err_text = " ".join(map(str, report.errors))
            self.assertIn("observable=None", err_text)
            self._assert_no_traceback_in_errors(report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 7: API schema drift — Label.create returns non-dict → ValueError contract ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_label_create_returns_non_dict_raises_value_error(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        _api_client_mock,
    ):
        """Label.create returns non-dict → connector raises ValueError, partial state has observable + labels=[]."""
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            task_id = uuid()
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, task_id)
            except Exception:
                pass  # In CI, after_run_failed re-raises; report is already FAILED

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.FAILED)

            err_text = " ".join(map(str, report.errors))
            self.assertIn("Invalid response from OpenCTI Label.create", err_text)
            partial_msgs = _partial_state_errors(report)
            self.assertEqual(len(partial_msgs), 1)
            self.assertIn("observable=obs-1", err_text)
            self.assertIn("labels=[]", err_text)
            self.assertEqual(len(report.errors), 2)
            self._assert_no_traceback_in_errors(report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Optional: live integration (env-guarded) ---
    @skipUnless(
        os.getenv("OPENCTI_URL") and os.getenv("OPENCTI_TOKEN"),
        "OpenCTI live test not configured",
    )
    def test_opencti_live_integration(self):
        config = self._get_opencti_config()
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
        analyzable = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        job = Job.objects.create(
            analyzable=analyzable,
            user=self.superuser,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.connectors_to_execute.set([config])
        try:
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, uuid())
            except Exception:
                pass  # In CI, after_run_failed re-raises on failure
            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertIn(
                report.status,
                [ConnectorReport.STATUSES.SUCCESS, ConnectorReport.STATUSES.FAILED],
            )
        finally:
            self._cleanup_test_objects(job, config, pcs)
