import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class GoReSym(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "executable_analyzer"
    url: str = "http://malware_tools_analyzers:4002/goresym"
    # interval between http request polling
    poll_distance: int = 5
    # http request polling max number of tries
    max_tries: int = 5
    default: bool = False
    paths: bool = False
    types: bool = False
    manual: str = ""
    version: str = ""

    def update(self) -> bool:
        pass

    def getArgs(self):
        args = []
        if self.default:
            args.append("-d")
        if self.paths:
            args.append("-p")
        if self.types:
            args.append("-t")
        if self.manual:
            args.append("-m " + self.manual)
        if self.version:
            args.append("-v " + self.version)
        return args

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = self.getArgs()
        args.append(f"@{fname}")
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        if "error" in result:
            # the error message may change based on the version of the program
            partial_error_keywords = ["failed", "no"]
            found_negative_clause = False
            if "pclntab" in result["error"]:
                for partial_error_keyword in partial_error_keywords:
                    if partial_error_keyword in result["error"]:
                        found_negative_clause = True
                        break
            if found_negative_clause:
                message = f"Not a GO-compiled file: {result['error']}"
                logger.warning(message)
                raise AnalyzerRunException(message)
            raise AnalyzerRunException(result["error"])
        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
                "report": {
                    "Version": "1.22.3",
                    "BuildId": """nwVuB9ChiwRxUV3uqogj
                    /gqLuN_Lt0hiTuOBT4YDw
                /7ArmhPs-KKm8m0kwm8Ud/RNgWKMZv5-p8k3r8fJCp""",
                    "Arch": "amd64",
                    "OS": "linux",
                    "TabMeta": {
                        "VA": 8261824,
                        "Version": "1.20",
                        "Endianess": "LittleEndian",
                        "CpuQuantum": 1,
                        "CpuQuantumStr": "x86/x64/wasm",
                        "PointerSize": 8,
                    },
                    "ModuleMeta": {
                        "VA": 10005792,
                        "TextVA": 4198400,
                        "Types": 7045120,
                        "ETypes": 8248647,
                        "Typelinks": {"Data": 8251936, "Len": 1791, "Capacity": 1791},
                        "ITablinks": {"Data": 8259104, "Len": 339, "Capacity": 339},
                        "LegacyTypes": {"Data": 0, "Len": 0, "Capacity": 0},
                    },
                    "Types": None,
                    "Interfaces": None,
                    "BuildInfo": {
                        "GoVersion": "go1.22.3",
                        "Path": "github.com/g4ze/byoc/reverse-proxy",
                        "Main": {
                            "Path": "github.com/g4ze/byoc",
                            "Version": "(devel)",
                            "Sum": "",
                            "Replace": None,
                        },
                        "Deps": [
                            {
                                "Path": "github.com/joho/godotenv",
                                "Version": "v1.5.1",
                                "Sum": """h1:7eLL/
                                +HRGLY0ldzfGMeQkb7vMd0as4CfYvUVzLqw0N0=""",
                                "Replace": None,
                            },
                            {
                                "Path": "github.com/lib/pq",
                                "Version": "v1.10.9",
                                "Sum": """h1:YXG7RB+JIjhP29X
                                +OtkiDnYaXQwpS4JEWq7dtCCRUEw=""",
                                "Replace": None,
                            },
                        ],
                        "Settings": [
                            {"Key": "-buildmode", "Value": "exe"},
                            {"Key": "-compiler", "Value": "gc"},
                            {"Key": "CGO_ENABLED", "Value": "1"},
                            {"Key": "CGO_CFLAGS", "Value": ""},
                            {"Key": "CGO_CPPFLAGS", "Value": ""},
                            {"Key": "CGO_CXXFLAGS", "Value": ""},
                            {"Key": "CGO_LDFLAGS", "Value": ""},
                            {"Key": "GOARCH", "Value": "amd64"},
                            {"Key": "GOOS", "Value": "linux"},
                            {"Key": "GOAMD64", "Value": "v1"},
                            {"Key": "vcs", "Value": "git"},
                            {
                                "Key": "vcs.revision",
                                "Value": "34e6cafd47a85a15e9aeedd63786a2ba72e5b301",
                            },
                            {"Key": "vcs.time", "Value": "2024-06-24T07:44:25Z"},
                            {"Key": "vcs.modified", "Value": "true"},
                        ],
                    },
                    "Files": None,
                    "UserFunctions": [
                        {
                            "Start": 7043712,
                            "End": 7043758,
                            "PackageName": "main",
                            "FullName": "main.main.NewSingleHostReverseProxy.func1",
                        },
                    ],
                    "StdFunctions": None,
                }
            },
            200,
        )
