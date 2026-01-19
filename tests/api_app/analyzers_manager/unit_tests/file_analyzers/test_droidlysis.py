from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.droidlysis import DroidLysis

from .base_test_class import BaseFileAnalyzerTest


class TestDroidLysis(BaseFileAnalyzerTest):
    analyzer_class = DroidLysis

    def get_mocked_response(self):
        # Mock the _docker_run method to return sample DroidLysis analysis results
        mock_response = {
            "analysis_complete": True,
            "file_info": {
                "filename": "sample.apk",
                "file_type": "Android APK",
                "file_size": 2048576,
            },
            "static_analysis": {
                "permissions": [
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                ],
                "activities": ["com.example.MainActivity", "com.example.LoginActivity"],
                "services": ["com.example.BackgroundService"],
                "receivers": ["com.example.NetworkReceiver"],
            },
            "security_analysis": {
                "suspicious_permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                ],
                "crypto_usage": ["AES encryption detected", "Base64 encoding found"],
                "network_analysis": {
                    "urls_found": [
                        "https://api.example.com",
                        "http://malicious-domain.com",
                    ],
                    "ip_addresses": ["192.168.1.1", "10.0.0.1"],
                },
            },
            "risk_assessment": {
                "risk_level": "medium",
                "total_score": 65,
                "categories": {"privacy": 40, "security": 70, "malware": 30},
            },
            "detailed_report": {
                "manifest_analysis": "AndroidManifest.xml parsed successfully",
                "code_analysis": "Decompiled classes analyzed",
                "resource_analysis": "Resources extracted and examined",
            },
        }

        return patch.object(DroidLysis, "_docker_run", return_value=mock_response)
