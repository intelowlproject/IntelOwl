# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
from unittest import skipUnless
from unittest.mock import patch

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.connectors_manager.connectors.opencti import OpenCTI
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.models import Job, Parameter, PluginConfig, Tag
from tests import CustomTestCase


# Connector uses pycti.Identity(inst).create(...), i.e. class(instance).method().
# Patching pycti.Identity.create does not intercept instance calls in all environments.
# Patch the CLASS so pycti.Identity(...) returns a mock; configure .return_value.create etc.
def _partial_state_errors(report):
    """Errors that contain the partial-state contract message."""
    return [e for e in report.errors if "Created IDs:" in str(e)]


class OpenCTIConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def _get_opencti_config(self):
        return ConnectorConfig.objects.get(name="OpenCTI")

    def _create_plugin_configs(self, config):
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

    def _cleanup_test_objects(self, job, config, pcs):
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

    # --- Test 1: Failure after observable creation ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_failure_after_observable_creation_partial_state_reported(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        _api_client_mock,
    ):
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.side_effect = Exception("label failure")

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
            self.assertIn("OpenCTI partial state detected", partial_msgs[0])
            self.assertEqual(len(report.errors), 2)

            err_text = " ".join(map(str, report.errors))
            self.assertIn("observable=obs-1", err_text)
            self.assertIn("labels=[]", err_text)
            self._assert_no_traceback_in_errors(report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 2: Failure after report creation ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.ExternalReference")
    @patch("pycti.Report")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_failure_after_report_creation_partial_state_reported(
        self,
        marking_mock,
        identity_mock,
        stix_observable_mock,
        label_mock,
        report_mock,
        external_ref_mock,
        _api_client_mock,
    ):
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.side_effect = Exception("external ref failure")

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
            self.assertIn("observable=obs-1", err_text)
            self.assertIn("report=report-1", err_text)
            self.assertIn("label-1", err_text)
            self._assert_no_traceback_in_errors(report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

    # --- Test 3: Failure after external reference but before linking ---
    @patch.object(OpenCTI, "_monkeypatch", classmethod(lambda cls: None))
    @patch("pycti.OpenCTIApiClient")
    @patch("pycti.StixDomainObject")
    @patch("pycti.ExternalReference")
    @patch("pycti.Report")
    @patch("pycti.Label")
    @patch("pycti.StixCyberObservable")
    @patch("pycti.Identity")
    @patch("pycti.MarkingDefinition")
    def test_failure_after_external_reference_before_linking_partial_state(
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
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = {"id": "label-1"}
        report_mock.return_value.create.return_value = {"id": "report-1"}
        external_ref_mock.return_value.create.return_value = {"id": "ext-ref-1"}
        stix_domain_mock.return_value.add_external_reference.side_effect = Exception("link failure")

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
            self.assertIn("external_reference=ext-ref-1", err_text)
            self.assertIn("report=report-1", err_text)
            self.assertIn("observable=obs-1", err_text)
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
