# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MalcoreScan(FileAnalyzer):
    base_url = "https://api.malcore.io/api/"
    _api_key_name: str
    max_tries: int
    poll_distance: int

    def update(self) -> bool:
        pass

    def run(self):
        self.headers = {"apiKey": self._api_key_name}

        binary = self.read_file_bytes()
        files = {"filename1": binary}
        logger.info(f"Sending {self.md5} to Malcore")
        response = requests.post(
            self.base_url + "upload", headers=self.headers, files=files
        )
        response.raise_for_status()

        try:
            uuid = response.json()["data"]["data"]["uuid"]
        except TypeError:
            raise AnalyzerRunException(f"Failed analysis for {self.md5}")

        for _try in range(self.max_tries):
            logger.info(f"polling malcore try #{_try + 1}")
            self.result = self._get_status(uuid)["data"]
            if "status" not in self.result and "msg" not in self.result:
                logger.info(f"Malcore analysis successfully retrieved for {self.md5}")
                break

            time.sleep(self.poll_distance)

        return self.result

    def _get_status(self, uuid):
        payload = {"uuid": uuid}
        response = requests.post(
            self.base_url + "status", headers=self.headers, json=payload
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        response = {
            "dfi": {"results": {}},
            "hashes": {
                "md5": "c78655bc80301d76ed4fef1c1ea40a7d",
                "sha1": "619652b42afe5fb0e3719d7aeda7a5494ab193e8",
                "crc32": "0x65ae1d65",
                "sha256": "93b2ed4004ed5f7f3039dd7ecbd22c7e4e24b6373b4d9ef8d6e45a179b13a5e8",  # noqa
                "sha512": "619652b42afe5fb0e3719d7aeda7a5494ab193e8",
                "ssdeep": "768:vWkX7q+f5TYvVeZMmn+0C4xirEbvK/PK:vX5fhuZE5ZvK/PK",
                "id_hash": "71a6382fc16be85e7829fff40676702335a16ada35feb38e55deba71c28e9191",  # noqa
                "imphash": "a72a57a50050874d785495b82d201cf8",
            },
            "exports": {"results": []},
            "hexdump": {
                "results": """0000000001:\t4d5a90000300000004000000\tMZ..........\n
                0000000002:\tffff0000b800000000000000\t............\n
                0000000003:\t400000000000000000000000\t@...........\n
                0000000004:\t000000000000000000000000\t............\n
                0000000005:\t000000000000000000000000\t............\n
                0000000006:\te80000000e1fba0e00b409cd\t............"""
            },
            "imports": {
                "results": {
                    "import_hashes": [
                        ["AddAccessAllowedAce", "0x4247dc71"],
                        ["GetLengthSid", "0xf32009f9"],
                    ],
                    "import_location": {
                        "ntdll.dll": [
                            {"name": "RtlSubAuthoritySid", "address": "0x100005080"},
                            {"name": "RtlLengthRequiredSid", "address": "0x100005088"},
                        ],
                        "msvcrt.dll": [
                            {"name": "?terminate@@YAXXZ", "address": "0x100005008"},
                            {"name": "__set_app_type", "address": "0x100005010"},
                        ],
                        "rpcrt4.dll": [
                            {"name": "I_RpcMapWin32Status", "address": "0x100005318"},
                            {
                                "name": "RpcMgmtSetServerStackSize",
                                "address": "0x100005320",
                            },
                            {
                                "name": "RpcServerUnregisterIfEx",
                                "address": "0x100005348",
                            },
                        ],
                        "advapi32.dll": [
                            {
                                "name": "SetSecurityDescriptorDacl",
                                "address": "0x100005298",
                            },
                            {
                                "name": "InitializeSecurityDescriptor",
                                "address": "0x1000052a0",
                            },
                        ],
                        "kernel32.dll": [
                            {"name": "__C_specific_handler", "address": "0x100005060"},
                            {"name": "RtlCaptureContext", "address": "0x1000050e8"},
                        ],
                        "ucrtbase.dll": [
                            {"name": "memcpy", "address": "0x100005000"},
                            {"name": "__setusermatherr", "address": "0x100005028"},
                            {"name": "_initterm", "address": "0x100005038"},
                            {"name": "exit", "address": "0x100005040"},
                            {"name": "_cexit", "address": "0x100005048"},
                            {"name": "_exit", "address": "0x100005050"},
                            {"name": "memset", "address": "0x100005070"},
                        ],
                    },
                    "raw_discovered_imports": [
                        ["0x100005000", "memcpy"],
                        ["0x100005008", "?terminate@@YAXXZ"],
                    ],
                }
            },
            "strings": {
                "results": """|$ f\n0A_A^A]A\\_\n</security>\n
                program\n\\$@H\nL$DI\nVWATAUAVH\n|$0H\n@.rsrc\n|$@L\n
                L$\H\nCoInitializeSecurity\nl$HH\nDL$h\ntaI;\nmemset\nHeapAlloc
                \nntdll.dll\n\\$`H\nRegQueryValueExW\n A]A\\_
                \nSetSecurityDescriptorDacl\nLoadLibraryExA\nL$0H\nx ATAUAVH\n
                LoadLibraryExW\noD$ f\nServices</description>\n
                <requestedPrivileges>\nCoInitializeEx\nRtlSubAuthorityCountSid
                \nHeapFree\nD$xA\nD$xL\nD$xH\nD$xI\n_cexit\nfD"""
            },
            "assembly": {
                "results": """sub rsp, 0x28\ncall fcn.1000020c0\nadd rsp, 0x28\njmp
                0x100002484\nn:\to\tp\nn:\to\tp\nn:\to\tp\nn:\to\tp\nn:\to\tp\nn:
                \to\tp\nn:\to\tp\nn:\to\tp\nn:\to\tp\nmov qword [var_8h], rsi\nmov qword
                [var_10h], rdi\nmov qword [var_18h], r12\npush r13\nsub rsp, 0x30\n
                mov rax, qword gs:[0x30]\n"""
            },
            "sections": {
                "results": """.text:\t6.04842129742\n.rdata:\t4.93709917348\n
                .data:\t0.557689615735\n.pdata:\t4.30188925316\n
                .rsrc:\t3.77082476018\n.reloc:\t1.10557339112\n"""
            },
            "exif_data": {
                "results": {
                    "file_size": "27136",
                    "mime_type": "application/x-msdownload",
                    "code_signature": "48 83 ec 28 e8 4b fc ff ff 48",
                }
            },
            "file_type": {"results": "PE"},
            "yara_rules": {
                "results": [
                    [
                        "Embedded_PE",
                        """Discover embedded PE files, without relying on
                        easily stripped/modified header strings.""",
                    ],
                    ["exe", "Checks if the program is an EXE file"],
                    [
                        "custom YARA rule",
                        (
                            "rule MYG___MALWARE__71a6382fc16be85e7"
                            "829fff40676702335a16ada35feb38e55"
                            "deba71c28e9191_tmp {\n\tmeta:\n\t\t"
                            'author = "Malcore Yara Generator"\n\t\t'
                            'ref = "https://malcore.io"\n\t\t'
                            'copyright = "Internet 2.0 Pty Ltd"\n\t\tfile_sha256 = '
                            '"93b2ed4004ed5f7f3039dd7ecbd22c7e4e24b6'
                            '373b4d9ef8d6e45a179b13a5e8"\n\n\t'
                            "strings:\n\t\t// specific strings found"
                        ),
                    ],
                ]
            },
            "architecture": {"results": 64},
            "threat_score": {
                "results": {
                    "score": "19.07/100",
                    "signatures": [
                        {
                            "info": {
                                "title": "File Entropy",
                                "description": """File entropy is the randomness
                                 of a file measured on a scale of 1-8. Higher
                                 entropy potentially indicates packed or
                                 encrypted data such as payloads or hidden PE files
                                 within the program. The higher the entropy the more
                                 likely it is that that program is encrypted
                                 or packed.""",
                            },
                            "discovered": 5.392278962506853,
                        },
                        {
                            "info": {
                                "title": "Suspicious Assembly",
                                "description": """Suspicious assembly calls are
                                 calls that are using jumps, calls, or xor in
                                 quick succession of one another, these are
                                 potentially indicators of on the fly loading
                                 of imports (dynamic import loading), cryptographic
                                 intentions (such as ransomware, or encryption
                                 /decryption techniques), or possibly even
                                 sandbox evasion. These are suspicious in
                                 nature due to the file type.""",
                            },
                            "discovered": [
                                [
                                    "mov rax, qword gs:[0x30]",
                                    "mov rdi, qword [rax + 8]",
                                    "xor r12d, r12d",
                                    "xor eax, eax",
                                    "lock cmpxchg qword [0x100007040], rdi",
                                    "jne 0x100002580",
                                ],
                                [
                                    "mov dword [0x10000705c], 2",
                                    "test r12d, r12d",
                                    "jne 0x100002557",
                                    "xor eax, eax",
                                    "xchg qword [0x100007040], rax",
                                    "cmp qword [0x100007760], 0",
                                ],
                            ],
                        },
                    ],
                }
            },
            "threat_summary": {
                "results": {
                    "iocs": {
                        "sha256": "93b2ed4004ed5f7f3039dd7ecbd22c7e4e24b6373b4d9ef8d6e45a179b13a5e8",  # noqa
                        "strings": [
                            'version="5.1.0.0"',
                            'version="5.1.0.0"',
                        ],
                    },
                    "file_type": "PE",
                    "threat_level": {
                        "score": "19.07/100",
                        "signatures": [
                            "File Entropy",
                            "Suspicious Assembly",
                        ],
                    },
                }
            },
            "similar_samples": {},
            "dynamic_analysis": {
                "parsed_output": [
                    {
                        "dll_name": "KERNEL32",
                        "location": "0x1000020f5",
                        "function_called": "GetSystemTimeAsFileTime",
                        "arguments_passed": ["0x127ff88"],
                        "function_return_value": "None",
                        "known_suspicious_function": False,
                    },
                    {
                        "dll_name": "KERNEL32",
                        "location": "0x100002129",
                        "function_called": "QueryPerformanceCounter",
                        "arguments_passed": ["0x127ff90"],
                        "function_return_value": "0x1",
                        "known_suspicious_function": False,
                    },
                ],
                "dynamic_analysis": [{"error": "unable to emulate"}],
                "misc_information": [
                    {
                        "raw_output": [
                            {
                                "address": "0x1000020f5",
                                "api_call": """KERNEL32.GetSystemTimeAsFileTime(0x127ff88)""",  # noqa
                                "return_value": "None",
                            },
                            {
                                "address": "0x100002100",
                                "api_call": "API-MS-Win-Core-ProcessThreads-L1-1-0.GetCurrentProcessId()",  # noqa
                                "return_value": "0x420",
                            },
                        ]
                    }
                ],
            },
            "packer_information": {
                "results": [
                    {"percent": "64.25%", "packer_name": "Pe123 v2006.4.4-4.1"},
                    {
                        "percent": "64.06%",
                        "packer_name": "Hying's PE-Armor 0.75.exe -> Hying [CCG] (h",
                    },
                    {"percent": "63.21%", "packer_name": "dePACK -> deNUL"},
                ]
            },
            "phone_app_analysis": {"results": []},
            "interesting_strings": {
                "results": [
                    '    version="5.1.0.0"',
                    'version="5.1.0.0"',
                    "0.00",
                    "RegCloseKey",
                    "RegOpenKeyExW",
                ]
            },
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(response, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
