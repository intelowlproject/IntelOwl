# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from api_app.connectors_manager.connectors.opencti import OpenCTI
from tests.api_app.connectors_manager.unit_tests.base_test_class import BaseConnectorTest

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


class OpenCTIConnectorTestCase(BaseConnectorTest):
    connector_class = OpenCTI

    @classmethod
    def get_extra_config(cls) -> dict:
        """Provide static plugin configurations avoiding Django database models."""
        return {
            "_url_key_name": "https://opencti.test",
            "_api_key_name": "test-token",
            "ssl_verify": False,
            "proxies": "",
            "tlp": {"type": "clear", "color": "white", "x_opencti_order": 1},
            "job_id": 51,
        }

    @classmethod
    def get_mocked_response(cls):
        """Define the default happy-path configuration for the generic base execution test."""
        mock_id = MagicMock()
        mock_id.return_value.create.return_value = {"id": "org-1"}

        mock_mark = MagicMock()
        mock_mark.return_value.create.return_value = {"id": "mark-1"}

        mock_obs = MagicMock()
        mock_obs.return_value.create.return_value = {"id": "obs-1"}

        mock_lbl = MagicMock()
        mock_lbl.return_value.create.return_value = {"id": "label-1"}

        mock_rep = MagicMock()
        mock_rep.return_value.create.return_value = {"id": "report-1"}

        mock_ref = MagicMock()
        mock_ref.return_value.create.return_value = {"id": "ext-ref-1"}

        return [
            patch("api_app.connectors_manager.connectors.opencti.pycti.OpenCTIApiClient"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Identity", new=mock_id),
            patch("api_app.connectors_manager.connectors.opencti.pycti.MarkingDefinition", new=mock_mark),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixCyberObservable", new=mock_obs),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Label", new=mock_lbl),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Report", new=mock_rep),
            patch("api_app.connectors_manager.connectors.opencti.pycti.ExternalReference", new=mock_ref),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixDomainObject"),
        ]

    def _setup_connector(self):
        """Inject customized mock managers to simulate the internal Django API objects."""
        connector = super()._setup_connector()

        # Isolate report logging arrays directly onto the runtime instance memory
        connector.report = MagicMock()
        connector.report.errors = []

        # Mock the related models sets loop used during label generation
        mock_tag = MagicMock()
        mock_tag.label = "testtag"
        mock_tag.color = "#ff0000"
        connector._job.tags = MagicMock()
        connector._job.tags.all.return_value = [mock_tag]

        # Mock query string values inside report descriptors
        mock_analyzers = MagicMock()
        mock_analyzers.all.return_value.values_list.return_value = ["VirusTotal"]
        connector._job.analyzers_to_execute = mock_analyzers

        # Avoid real datetime formatting mutations
        mock_date = MagicMock()
        mock_date.strftime.return_value = "2026-06-16T12:00:00Z"
        connector._job.received_request_time = mock_date

        return connector

    def test_partial_state_failure_scenarios(self):
        """Iterate localized failure targets via subtests while verifying partial state logs."""
        for scenario in PARTIAL_STATE_SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                connector = self._setup_connector()

                mock_id = MagicMock()
                mock_id.return_value.create.return_value = {"id": "org-1"}
                mock_mark = MagicMock()
                mock_mark.return_value.create.return_value = {"id": "mark-1"}
                mock_obs = MagicMock()
                mock_obs.return_value.create.return_value = {"id": "obs-1"}
                mock_lbl = MagicMock()
                mock_lbl.return_value.create.return_value = {"id": "label-1"}
                mock_rep = MagicMock()
                mock_rep.return_value.create.return_value = {"id": "report-1"}
                mock_ref = MagicMock()
                mock_ref.return_value.create.return_value = {"id": "ext-ref-1"}
                mock_dom = MagicMock()

                # Sabotage the execution flow depending on specific target
                if scenario["fail_mock"] == "label":
                    mock_lbl.return_value.create.side_effect = Exception("label failure")
                elif scenario["fail_mock"] == "external_ref":
                    mock_ref.return_value.create.side_effect = Exception("external ref failure")
                elif scenario["fail_mock"] == "link":
                    mock_dom.return_value.add_external_reference.side_effect = Exception("link failure")

                patches = [
                    patch("api_app.connectors_manager.connectors.opencti.pycti.OpenCTIApiClient"),
                    patch("api_app.connectors_manager.connectors.opencti.pycti.Identity", new=mock_id),
                    patch(
                        "api_app.connectors_manager.connectors.opencti.pycti.MarkingDefinition", new=mock_mark
                    ),
                    patch(
                        "api_app.connectors_manager.connectors.opencti.pycti.StixCyberObservable",
                        new=mock_obs,
                    ),
                    patch("api_app.connectors_manager.connectors.opencti.pycti.Label", new=mock_lbl),
                    patch("api_app.connectors_manager.connectors.opencti.pycti.Report", new=mock_rep),
                    patch(
                        "api_app.connectors_manager.connectors.opencti.pycti.ExternalReference", new=mock_ref
                    ),
                    patch(
                        "api_app.connectors_manager.connectors.opencti.pycti.StixDomainObject", new=mock_dom
                    ),
                ]

                with ExitStack() as stack:
                    for p in patches:
                        stack.enter_context(p)

                    with self.assertRaises(Exception):
                        connector.run()

                    partial_msgs = [e for e in connector.report.errors if "Created IDs:" in str(e)]
                    self.assertEqual(len(partial_msgs), 1)

                    err_text = " ".join(map(str, connector.report.errors))
                    for substr in scenario["expected_ids"]:
                        self.assertIn(substr, err_text)

    def test_organization_and_marking_called_only_once(self):
        """Properties caching validation checking that static initialization calls occur once."""
        connector = self._setup_connector()

        # Mock the specific objects we want to assert on
        mock_id = MagicMock()
        mock_id.return_value.create.return_value = {"id": "org-1"}
        mock_mark = MagicMock()
        mock_mark.return_value.create.return_value = {"id": "mark-1"}

        # Provide safe return dictionaries for the downstream objects
        # so they do not crash the pipeline before the assertions are reached.
        mock_obs = MagicMock()
        mock_obs.return_value.create.return_value = {"id": "obs-1"}
        mock_lbl = MagicMock()
        mock_lbl.return_value.create.return_value = {"id": "label-1"}
        mock_rep = MagicMock()
        mock_rep.return_value.create.return_value = {"id": "report-1"}
        mock_ref = MagicMock()
        mock_ref.return_value.create.return_value = {"id": "ext-ref-1"}

        patches = [
            patch("api_app.connectors_manager.connectors.opencti.pycti.OpenCTIApiClient"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Identity", new=mock_id),
            patch("api_app.connectors_manager.connectors.opencti.pycti.MarkingDefinition", new=mock_mark),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixCyberObservable", new=mock_obs),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Label", new=mock_lbl),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Report", new=mock_rep),
            patch("api_app.connectors_manager.connectors.opencti.pycti.ExternalReference", new=mock_ref),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixDomainObject"),
        ]

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)

            connector.run()

            mock_id.return_value.create.assert_called_once()
            mock_mark.return_value.create.assert_called_once()

    def test_observable_create_returns_non_dict_handled_safely(self):
        """Silently handled non-dictionary returns must gracefully trigger an observable failure check."""
        connector = self._setup_connector()
        mock_obs = MagicMock()
        mock_obs.return_value.create.return_value = None

        patches = [
            patch("api_app.connectors_manager.connectors.opencti.pycti.OpenCTIApiClient"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Identity"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.MarkingDefinition"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixCyberObservable", new=mock_obs),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Label"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Report"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.ExternalReference"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixDomainObject"),
        ]

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            with self.assertRaises(ValueError):
                connector.run()

            err_text = " ".join(map(str, connector.report.errors))
            self.assertIn("observable=None", err_text)

    def test_label_create_returns_non_dict_raises_value_error(self):
        """Malformed label creation returns must cancel pipeline propagation immediately."""
        connector = self._setup_connector()
        mock_obs = MagicMock()
        mock_obs.return_value.create.return_value = {"id": "obs-1"}
        mock_lbl = MagicMock()
        mock_lbl.return_value.create.return_value = None

        patches = [
            patch("api_app.connectors_manager.connectors.opencti.pycti.OpenCTIApiClient"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Identity"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.MarkingDefinition"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixCyberObservable", new=mock_obs),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Label", new=mock_lbl),
            patch("api_app.connectors_manager.connectors.opencti.pycti.Report"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.ExternalReference"),
            patch("api_app.connectors_manager.connectors.opencti.pycti.StixDomainObject"),
        ]

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            with self.assertRaises(ValueError) as ctx:
                connector.run()

            self.assertIn("Invalid response from OpenCTI Label.create", str(ctx.exception))
            err_text = " ".join(map(str, connector.report.errors))
            self.assertIn("observable=obs-1", err_text)
            self.assertIn("labels=[]", err_text)

    def test_success_path_integrity(self):
        """Validates the exact shape of the returned OpenCTI dictionary contract."""
        connector = self._setup_connector()

        with self._apply_patches(self.get_mocked_response()):
            result = connector.run()

            # Enforce the strict API contract
            self.assertIsInstance(result, dict)
            self.assertIn("observable", result)
            self.assertIn("id", result["observable"])
            self.assertIn("report", result)
            self.assertIn("id", result["report"])
