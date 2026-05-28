# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from api_app.connectors_manager.connectors.abuse_submitter import AbuseSubmitter
from api_app.connectors_manager.exceptions import ConnectorRunException
from tests.api_app.connectors_manager.unit_tests.base_test_class import BaseConnectorTest


class AbuseSubmitterTestCase(BaseConnectorTest):
    connector_class = AbuseSubmitter

    @classmethod
    def get_mocked_response(cls):
        return [patch("django.core.mail.EmailMessage.send", return_value="Email sent")]

    def _create_mock_job(self, observable_name, observable_type):
        """
        Creates a mock job with the necessary hierarchy for the AbuseSubmitter connector.
        The hierarchy is: Job -> Parent Job -> Grandparent Job (Analyzable)
        """
        mock_job = super()._create_mock_job(observable_name, observable_type)

        mock_grandparent = SimpleNamespace()
        mock_grandparent.analyzable = mock_job.analyzable

        mock_parent = SimpleNamespace()
        mock_parent.parent_job = mock_grandparent

        mock_job.parent_job = mock_parent

        return mock_job

    def test_abuse_submitter_missing_hierarchy(self):
        """
        Verify that AbuseSubmitter raises ConnectorRunException when job hierarchy is missing.
        This tests the fix for the AttributeError crash.
        """

        mock_config = MagicMock()
        connector = AbuseSubmitter(mock_config)

        bad_job = self._create_mock_job("malicious.domain", "domain")
        bad_job.parent_job = None
        connector._job = bad_job

        # Verify subject raises ConnectorRunException
        with self.assertRaisesRegex(ConnectorRunException, "Job hierarchy is invalid"):
            _ = connector.subject

        # Verify body raises ConnectorRunException
        with self.assertRaisesRegex(ConnectorRunException, "Job hierarchy is invalid"):
            _ = connector.body

    def test_abuse_submitter_valid_hierarchy(self):
        """
        Verify that AbuseSubmitter correctly returns subject and body when hierarchy is valid.
        """

        # Create dummy config and instantiate
        mock_config = MagicMock()
        connector = self.connector_class(mock_config)
        connector._job = self._create_mock_job("malicious.domain", "domain")

        self.assertEqual(connector.subject, "Takedown domain request for malicious.domain")
        self.assertIn("Domain malicious.domain", connector.body)
