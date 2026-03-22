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

# Each scenario describes: where to inject the failure, which mock to break,
# and what substrings must appear in the partial-state error message.
PARTIAL_STATE_SCENARIOS = (
    {
        "name": "failure_after_observable",
        "fail_mock": "label",
        "expected_exception": "label failure",
        "expected_ids": ["observable=obs-1", "labels=[]"],
    },
    {
        "name": "failure_after_report",
        "fail_mock": "external_ref",
        "expected_exception": "external ref failure",
        "expected_ids": ["observable=obs-1", "report=report-1", "label-1"],
    },
    {
        "name": "failure_after_external_ref",
        "fail_mock": "link",
        "expected_exception": "link failure",
        "expected_ids": ["external_reference=ext-ref-1", "report=report-1", "observable=obs-1"],
    },
)


def _partial_state_errors(report):
    """Return error entries that contain the partial-state contract message."""
    return [e for e in report.errors if "Created IDs:" in str(e)]


def _apply_happy_path_defaults(mocks):
    """Wire up all pycti mocks to return valid dicts so the connector can proceed."""
    # subTest reuses patched objects, so reset them before each scenario.
    for key in ("identity", "marking", "observable", "label", "report", "external_ref", "stix_domain"):
        mocks[key].reset_mock()

    # reset_mock() does not clear nested child side_effect values, so clear them explicitly.
    mocks["label"].return_value.create.side_effect = None
    mocks["external_ref"].return_value.create.side_effect = None
    mocks["stix_domain"].return_value.add_external_reference.side_effect = None

    mocks["identity"].return_value.create.return_value = {"id": "org-1"}
    mocks["marking"].return_value.create.return_value = {"id": "mark-1"}
    mocks["observable"].return_value.create.return_value = {"id": "obs-1"}
    mocks["observable"].return_value.read.return_value = {"id": "obs-1"}
    mocks["label"].return_value.create.return_value = {"id": "label-1"}
    mocks["report"].return_value.create.return_value = {"id": "report-1"}
    mocks["report"].return_value.read.return_value = {"id": "report-1"}
    mocks["external_ref"].return_value.create.return_value = {"id": "ext-ref-1"}
    mocks["stix_domain"].return_value.add_external_reference.return_value = None
    mocks["report"].return_value.add_stix_object_or_stix_relationship.return_value = None


def _inject_failure_for_scenario(mocks, fail_mock):
    """Inject exactly one failure point while keeping the rest on the happy path."""
    failure_targets = {
        "label": (mocks["label"].return_value.create, "label failure"),
        "external_ref": (mocks["external_ref"].return_value.create, "external ref failure"),
        "link": (mocks["stix_domain"].return_value.add_external_reference, "link failure"),
    }
    try:
        target, message = failure_targets[fail_mock]
    except KeyError as exc:
        raise AssertionError(f"Unsupported fail_mock scenario: {fail_mock}") from exc
    target.side_effect = Exception(message)


class OpenCTIConnectorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    # -- Helpers (stateless where possible) --

    @staticmethod
    def _get_opencti_config():
        return ConnectorConfig.objects.get(name="OpenCTI")

    @staticmethod
    def _create_plugin_configs(config):
        """Create required PluginConfig entries for OpenCTI (url_key_name, api_key_name)."""
        pcs = []
        for name in ("url_key_name", "api_key_name"):
            param = Parameter.objects.get(python_module=config.python_module, name=name)
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
        """Create Analyzable + Job + OpenCTI config. Returns (job, config, pcs)."""
        config = self._get_opencti_config()
        pcs = self._create_plugin_configs(config)
        analyzable = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job = Job.objects.create(
            analyzable=analyzable,
            user=self.superuser,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
        )
        job.connectors_to_execute.set([config])
        if add_tag:
            tag, _ = Tag.objects.get_or_create(label="testtag", defaults={"color": "#ff0000"})
            job.tags.add(tag)
        return job, config, pcs

    @staticmethod
    def _cleanup_test_objects(job, config, pcs):
        """Delete only objects created by this test."""
        try:
            ConnectorReport.objects.get(job=job, config=config).delete()
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

    def _collect_pycti_mocks(
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
        """Bundle positional patch args into a dict for _apply_happy_path_defaults / _inject_failure."""
        return {
            "marking": marking_mock,
            "identity": identity_mock,
            "observable": stix_observable_mock,
            "label": label_mock,
            "report": report_mock,
            "external_ref": external_ref_mock,
            "stix_domain": stix_domain_mock,
            "api_client": _api_client_mock,
        }

    # -- Tests --

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
    ):
        """Iterate failure points via subTest; each verifies partial-state tracking."""
        mocks = self._collect_pycti_mocks(
            marking_mock,
            identity_mock,
            stix_observable_mock,
            label_mock,
            report_mock,
            external_ref_mock,
            stix_domain_mock,
            _api_client_mock,
        )

        for scenario in PARTIAL_STATE_SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                _apply_happy_path_defaults(mocks)
                _inject_failure_for_scenario(mocks, scenario["fail_mock"])

                job, config, pcs = self._setup_job_with_opencti(add_tag=True)
                try:
                    connector = OpenCTI(config)
                    try:
                        connector.start(job.pk, {}, uuid())
                    except Exception:
                        pass

                    report = ConnectorReport.objects.get(job=job, config=config)
                    self.assertEqual(report.status, ConnectorReport.STATUSES.FAILED)

                    partial_msgs = _partial_state_errors(report)
                    self.assertEqual(len(partial_msgs), 1)
                    self.assertEqual(len(report.errors), 2)
                    self.assertIn(
                        "OpenCTI partial state detected after exception:",
                        partial_msgs[0],
                    )

                    non_partial_errors = [str(e) for e in report.errors if "Created IDs:" not in str(e)]
                    self.assertTrue(non_partial_errors)
                    self.assertIn(scenario["expected_exception"], non_partial_errors[0])

                    err_text = " ".join(map(str, report.errors))
                    for substr in scenario["expected_ids"]:
                        self.assertIn(substr, err_text)
                    self._assert_no_traceback_in_errors(report)
                finally:
                    self._cleanup_test_objects(job, config, pcs)

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
        mocks = self._collect_pycti_mocks(
            marking_mock,
            identity_mock,
            stix_observable_mock,
            label_mock,
            report_mock,
            external_ref_mock,
            stix_domain_mock,
            _api_client_mock,
        )
        _apply_happy_path_defaults(mocks)

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            connector = OpenCTI(config)
            connector.start(job.pk, {}, uuid())

            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertEqual(report.status, ConnectorReport.STATUSES.SUCCESS)
            self.assertEqual(report.errors, [])
            self.assertIsInstance(report.report, dict)
            self.assertIn("observable", report.report)
            self.assertIn("report", report.report)
        finally:
            self._cleanup_test_objects(job, config, pcs)

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
        mocks = self._collect_pycti_mocks(
            marking_mock,
            identity_mock,
            stix_observable_mock,
            label_mock,
            report_mock,
            external_ref_mock,
            stix_domain_mock,
            _api_client_mock,
        )
        _apply_happy_path_defaults(mocks)

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            connector = OpenCTI(config)
            connector.start(job.pk, {}, uuid())
            identity_mock.return_value.create.assert_called_once()
            marking_mock.return_value.create.assert_called_once()
        finally:
            self._cleanup_test_objects(job, config, pcs)

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
        """StixCyberObservable.create returns non-dict -> observable=None, fails safely."""
        mocks = self._collect_pycti_mocks(
            marking_mock,
            identity_mock,
            stix_observable_mock,
            label_mock,
            report_mock,
            external_ref_mock,
            stix_domain_mock,
            _api_client_mock,
        )
        _apply_happy_path_defaults(mocks)
        stix_observable_mock.return_value.create.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, uuid())
            except Exception:
                pass

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
        """Label.create returns non-dict -> ValueError with observable + labels=[] in partial state."""
        identity_mock.return_value.create.return_value = {"id": "org-1"}
        marking_mock.return_value.create.return_value = {"id": "mark-1"}
        stix_observable_mock.return_value.create.return_value = {"id": "obs-1"}
        label_mock.return_value.create.return_value = None

        job, config, pcs = self._setup_job_with_opencti(add_tag=True)
        try:
            connector = OpenCTI(config)
            try:
                connector.start(job.pk, {}, uuid())
            except Exception:
                pass

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
        analyzable = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
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
                pass
            report = ConnectorReport.objects.get(job=job, config=config)
            self.assertIn(
                report.status,
                [ConnectorReport.STATUSES.SUCCESS, ConnectorReport.STATUSES.FAILED],
            )
        finally:
            self._cleanup_test_objects(job, config, pcs)
