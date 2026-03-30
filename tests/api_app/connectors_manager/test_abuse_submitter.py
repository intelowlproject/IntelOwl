from unittest.mock import MagicMock

from api_app.connectors_manager.connectors.abuse_submitter import AbuseSubmitter
from api_app.connectors_manager.exceptions import ConnectorRunException
from tests import CustomTestCase


class AbuseSubmitterTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        # Mocking the ConnectorConfig
        self.mock_config = MagicMock()
        # Mocking the job hierarchy
        self.mock_job = MagicMock()

    def test_abuse_submitter_missing_hierarchy(self):
        """
        Verify that AbuseSubmitter raises ConnectorRunException when job hierarchy is missing.
        This tests the fix for the AttributeError crash.
        """
        self.mock_job.parent_job = None
        connector = AbuseSubmitter(self.mock_config)
        connector._job = self.mock_job

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
        # Create a valid hierarchy: Job -> Parent -> Grandparent (Analyzable)
        mock_parent = MagicMock()
        mock_grandparent = MagicMock()
        mock_analyzable = MagicMock()
        mock_analyzable.name = "malicious.domain"

        self.mock_job.parent_job = mock_parent
        mock_parent.parent_job = mock_grandparent
        mock_grandparent.analyzable = mock_analyzable

        connector = AbuseSubmitter(self.mock_config)
        connector._job = self.mock_job

        self.assertEqual(connector.subject, "Takedown domain request for malicious.domain")
        self.assertIn("Domain malicious.domain", connector.body)
