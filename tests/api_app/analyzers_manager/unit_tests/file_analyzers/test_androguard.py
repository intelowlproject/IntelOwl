from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.androguard import AndroguardAnalyzer

from .base_test_class import BaseFileAnalyzerTest


class TestAndroguardAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = AndroguardAnalyzer

    def get_mocked_response(self):
        # Mock the APK object
        mock_apk = MagicMock()
        mock_apk = MagicMock()

        # Configure APK mock methods to return sample data
        mock_apk.get_app_name.return_value = "TestApp"
        mock_apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
        ]
        mock_apk.get_activities.return_value = [
            "com.example.MainActivity",
            "com.example.SettingsActivity",
        ]
        mock_apk.get_requested_third_party_permissions.return_value = [
            "com.google.android.c2dm.permission.RECEIVE"
        ]
        mock_apk.get_providers.return_value = ["com.example.DataProvider"]
        mock_apk.get_features.return_value = [
            "android.hardware.camera",
            "android.hardware.location",
        ]
        mock_apk.get_receivers.return_value = ["com.example.NetworkReceiver"]
        mock_apk.get_services.return_value = ["com.example.BackgroundService"]
        mock_apk.is_valid_APK.return_value = True
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_max_sdk_version.return_value = "30"
        mock_apk.get_target_sdk_version.return_value = "29"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_androidversion_name.return_value = "1.0.0"

        # We mock AnalyzeAPK to return (apk, list_of_dex, analysis_obj)
        # We only really need apk in our tests
        analyze_apk_patch = patch(
            "api_app.analyzers_manager.file_analyzers.androguard.AnalyzeAPK",
            return_value=(mock_apk, tuple("sample_dex"), MagicMock())
        )
        
        # We also mock AnalyzeDex for dex files
        analyze_dex_patch = patch(
            "api_app.analyzers_manager.file_analyzers.androguard.AnalyzeDex",
            return_value=(MagicMock(), tuple("sample_dex"), MagicMock())
        )
        
        # Start the patches if needed by the test framework setup
        self.analyze_apk_mock = analyze_apk_patch.start()
        self.analyze_dex_mock = analyze_dex_patch.start()
        
        # Return none, or return the patches so base test can clean them up
        return analyze_apk_patch

