import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

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
        logger.info(f"Running {self.analyzer_name} on {self.filename} with args: {args}")
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
