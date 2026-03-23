from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings

from api_app.core.update_checker import check_for_update
from api_app.models import UpdateCheckStatus


@override_settings(TESTING=True)
class UpdateCheckerTests(TestCase):
    """Tests for IntelOwl update check system."""

    @staticmethod
    def setUp():
        UpdateCheckStatus.objects.all().delete()

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.UserEventQuerySet")
    @patch("api_app.core.update_checker.requests.get")
    def test_new_version_triggers_notification(self, mock_get, mock_user_events):
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v2.0.0"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        success, msg = check_for_update()

        self.assertTrue(success)
        self.assertIn("New IntelOwl version available", msg)
        mock_user_events.notify_admins.assert_called_once()

        state = UpdateCheckStatus.objects.get(pk=1)
        self.assertEqual(state.latest_version, "2.0.0")
        self.assertTrue(state.notified)

    @override_settings(INTEL_OWL_VERSION="2.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.UserEventQuerySet")
    @patch("api_app.core.update_checker.requests.get")
    def test_same_version_no_notification(self, mock_get, mock_user_events):
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v2.0.0"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        success, msg = check_for_update()

        self.assertTrue(success)
        self.assertIn("up to date", msg)
        mock_user_events.notify_admins.assert_not_called()

    @override_settings(INTEL_OWL_VERSION="3.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.requests.get")
    def test_local_version_ahead(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v2.0.0"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        success, msg = check_for_update()
        self.assertTrue(success)
        self.assertIn("Local version ahead", msg)

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL=None)
    def test_missing_update_url(self):
        success, msg = check_for_update()
        self.assertFalse(success)
        self.assertIn("UPDATE_CHECK_URL not configured", msg)

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch(
        "api_app.core.update_checker.requests.get",
        side_effect=__import__("requests").RequestException("boom"),
    )
    def test_fetch_error(self, mock_get):
        success, msg = check_for_update()
        self.assertFalse(success)
        self.assertIn("Failed to fetch", msg)

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.requests.get")
    def test_invalid_json_response(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError()
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        success, msg = check_for_update()
        self.assertFalse(success)
        self.assertIn("Invalid response", msg)

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.requests.get")
    def test_missing_tag_name(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        success, msg = check_for_update()
        self.assertFalse(success)
        self.assertIn("missing tag_name", msg)

    @override_settings(INTEL_OWL_VERSION="1.0.0", UPDATE_CHECK_URL="http://dummy")
    @patch("api_app.core.update_checker.UserEventQuerySet")
    @patch("api_app.core.update_checker.requests.get")
    def test_notification_sent_only_once(self, mock_get, mock_user_events):
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v2.0.0"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        check_for_update()
        check_for_update()

        self.assertEqual(mock_user_events.notify_admins.call_count, 1)
