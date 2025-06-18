# from unittest.mock import patch, MagicMock
# from api_app.analyzers_manager.models import MimeTypes
# from .base_test_class import BaseFileAnalyzerTest
# from api_app.analyzers_manager.file_analyzers.androguard import AndroguardAnalyzer


# class TestAndroguardAnalyzer(BaseFileAnalyzerTest):
#     analyzer_class = AndroguardAnalyzer

#     def get_mocked_response(self):
#         # Mock the androguard session and APK object
#         mock_session = MagicMock()
#         mock_apk = MagicMock()

#         # Configure APK mock methods to return sample data
#         mock_apk.get_app_name.return_value = "TestApp"
#         mock_apk.get_permissions.return_value = [
#             "android.permission.INTERNET",
#             "android.permission.ACCESS_NETWORK_STATE"
#         ]
#         mock_apk.get_activities.return_value = [
#             "com.example.MainActivity",
#             "com.example.SettingsActivity"
#         ]
#         mock_apk.get_requested_third_party_permissions.return_value = [
#             "com.google.android.c2dm.permission.RECEIVE"
#         ]
#         mock_apk.get_providers.return_value = [
#             "com.example.DataProvider"
#         ]
#         mock_apk.get_features.return_value = [
#             "android.hardware.camera",
#             "android.hardware.location"
#         ]
#         mock_apk.get_receivers.return_value = [
#             "com.example.NetworkReceiver"
#         ]
#         mock_apk.get_services.return_value = [
#             "com.example.BackgroundService"
#         ]
#         mock_apk.is_valid_APK.return_value = True
#         mock_apk.get_min_sdk_version.return_value = "21"
#         mock_apk.get_max_sdk_version.return_value = "30"
#         mock_apk.get_target_sdk_version.return_value = "29"
#         mock_apk.get_androidversion_code.return_value = "1"
#         mock_apk.get_androidversion_name.return_value = "1.0.0"

#         # Configure session mock methods
#         mock_session.addAPK.return_value = (None, mock_apk)  # Returns (a, apk) tuple
#         mock_session.addDEX.return_value = None

#         # Return the patch for get_default_session
#         return patch('androguard.misc.get_default_session', return_value=mock_session)
