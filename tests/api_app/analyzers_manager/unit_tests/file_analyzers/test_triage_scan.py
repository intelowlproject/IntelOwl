from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.triage_scan import TriageScanFile

from .base_test_class import BaseFileAnalyzerTest


class TestTriageScanFile(BaseFileAnalyzerTest):
    analyzer_class = TriageScanFile

    def get_extra_config(self):
        return {
            "max_tries": 5,
            "poll_distance": 2,
            "url": "https://api.tria.ge/v0/",
            "api_key": "test_api_key_12345",
            "final_report": {},
            "response": None,
            "events_response": None,
        }

    def get_mocked_response(self):
        # Mock successful session
        mock_session = MagicMock()

        # Mock POST response for sample submission
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "id": "sample_abc123def456",
            "status": "pending",
            "kind": "file",
            "filename": "malware.exe",
            "submitted": "2024-01-15T10:30:00Z",
        }
        mock_session.post.return_value = mock_post_response

        # Mock GET response for task results
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "tasks": {
                "behavioral1": {
                    "status": "completed",
                    "target": "malware.exe",
                    "score": 8,
                    "tags": ["trojan", "stealer"],
                    "analysis": {
                        "processes": [
                            {
                                "pid": 1234,
                                "ppid": 5678,
                                "name": "malware.exe",
                                "cmd": "malware.exe --silent",
                                "modules": ["ntdll.dll", "kernel32.dll"],
                            }
                        ],
                        "network": [
                            {
                                "protocol": "TCP",
                                "src": "192.168.1.100:49152",
                                "dst": "203.0.113.50:80",
                                "domain": "c2.malicious.com",
                            }
                        ],
                        "files": [
                            {
                                "name": "C:\\temp\\dropped.dll",
                                "operation": "create",
                                "md5": "deadbeefcafebabe1234567890abcdef",
                            }
                        ],
                        "registry": [
                            {
                                "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                "value": "malware.exe",
                                "operation": "set",
                            }
                        ],
                    },
                },
                "static1": {
                    "status": "completed",
                    "target": "malware.exe",
                    "score": 7,
                    "tags": ["packed", "suspicious"],
                    "analysis": {
                        "pe": {
                            "imports": ["CreateFileA", "WriteFile", "RegSetValueA"],
                            "sections": [".text", ".data", ".rsrc"],
                            "entropy": 7.2,
                            "timestamp": "2024-01-10T15:22:33Z",
                        },
                        "strings": [
                            "http://malicious.com/config",
                            "CreateMutexA",
                            "password123",
                        ],
                    },
                },
            },
            "sample": {
                "id": "sample_abc123def456",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "size": 4096,
                "kind": "file",
                "filename": "malware.exe",
            },
        }
        mock_session.get.return_value = mock_get_response

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.triage_scan.TriageMixin.__init__",
                return_value=None,
            ),
            patch.object(TriageScanFile, "session", mock_session),
            patch.object(TriageScanFile, "url", "https://api.tria.ge/v0/"),
            patch.object(TriageScanFile, "manage_submission_response", return_value=None),
        ]
