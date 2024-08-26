from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse


class Mobsf(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "file_analyzer"
    url: str = "http://malware_tools_analyzers:4002/mobsf"
    # interval between http request polling
    poll_distance: int = 2
    # http request polling max number of tries
    max_tries: int = 5

    def update(self):
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", "--json"]
        req_data = {"args": args}
        req_files = {fname: binary}

        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            # flake8: noqa
            {
                "report": {
                    "results": {
                        "android_logging": {
                            "files": [
                                {
                                    "file_path": "/tmp/tmpzpwdglcv/java_vuln.java",
                                    "match_lines": [19, 19],
                                    "match_string": '            Log.d("htbridge", "getAllRecords(): " + records.toString());',
                                    "match_position": [13, 73],
                                }
                            ],
                            "metadata": {
                                "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
                                "masvs": "MSTG-STORAGE-3",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#logs",
                                "description": "The App logs information. Please ensure that sensitive information is never logged.",
                                "owasp-mobile": "M1: Improper Platform Usage",
                            },
                        },
                        "android_safetynet_api": {
                            "metadata": {
                                "cwe": "CWE-353: Missing Support for Integrity Check",
                                "masvs": "MSTG-RESILIENCE-1",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1",
                                "description": "This app does not uses SafetyNet Attestation API that provides cryptographically-signed attestation, assessing the device's integrity. This check helps to ensure that the servers are interacting with the genuine app running on a genuine Android device. ",
                                "owasp-mobile": "M8: Code Tampering",
                            }
                        },
                        "android_root_detection": {
                            "metadata": {
                                "cwe": "CWE-919: Weaknesses in Mobile Applications",
                                "masvs": "MSTG-RESILIENCE-1",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection-mstg-resilience-1",
                                "description": "This app does not have root detection capabilities. Running a sensitive application on a rooted device questions the device integrity and affects users data.",
                                "owasp-mobile": "M8: Code Tampering",
                            }
                        },
                        "android_detect_tapjacking": {
                            "metadata": {
                                "cwe": "CWE-200: Information Exposure",
                                "masvs": "MSTG-PLATFORM-9",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-overlay-attacks-mstg-platform-9",
                                "description": "This app does not have capabilities to prevent tapjacking attacks. An attacker can hijack the user's taps and tricks him into performing some critical operations that he did not intend to.",
                                "owasp-mobile": "M1: Improper Platform Usage",
                            }
                        },
                        "android_prevent_screenshot": {
                            "metadata": {
                                "cwe": "CWE-200: Information Exposure",
                                "masvs": "MSTG-STORAGE-9",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots-mstg-storage-9",
                                "description": "This app does not have capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.",
                                "owasp-mobile": "M2: Insecure Data Storage",
                            }
                        },
                        "android_certificate_pinning": {
                            "metadata": {
                                "cwe": "CWE-295: Improper Certificate Validation",
                                "masvs": "MSTG-NETWORK-4",
                                "severity": "INFO",
                                "reference": "https://github.com/MobSF/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-4",
                                "description": "This app does not use a TLS/SSL certificate or public key pinning in code to detect or prevent MITM attacks in secure communication channel. Please verify if pinning is enabled in `network_security_config.xml`.",
                                "owasp-mobile": "M3: Insecure Communication",
                            }
                        },
                    },
                    "mobsfscan_version": "0.3.9",
                }
            },
            200,
        )
