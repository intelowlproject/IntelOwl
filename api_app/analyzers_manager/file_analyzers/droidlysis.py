import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class DroidLysis(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "android_analyzer"
    url: str = "http://malware_tools_analyzers:4002/droidlysis"
    # interval between http request polling
    poll_distance: int = 2
    # http request polling max number of tries
    max_tries: int = 10

    def update(self) -> bool:
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [
            "--input",
            f"@{fname}",
            "-o",
            "/opt/deploy/droidlysis/out/",
            "--config",
            "/opt/deploy/droidlysis/conf/general.conf",
        ]
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
                # mockup is made smaller as it was too big
                "kits": {
                    "flutter_libphonenumber": False,
                    "aitypemalvertingrelated": False,
                    "openalliancehuaweiadskit": False,
                    "quantumgraphqgraphappier": False,
                    "salesforcemarketingcloud": False,
                    "playtestcloudeventtracking": False,
                    "quadrantdataacquisitionsdk": False,
                    "analyticsbynpawyouborasuite": False,
                    "flutter_local_notifications": False,
                    "amazonmobileanalyticsamplify": False,
                    "gmobigo2reachgeneralmobilecorporation": False,
                },
                "filetype": 1,
                "file_size": 1165709,
                "file_small": False,
                "file_nb_dir": 94,
                "arm_properties": {
                    "possible_exploit": False,
                },
                "dex_properties": {
                    "odex": False,
                    "magic": 38,
                    "bad_sha1": False,
                    "thuxnder": False,
                    "big_header": False,
                    "bad_adler32": False,
                    "magic_unknown": False,
                },
                "file_innerzips": False,
                "file_nb_classes": 1340,
                "wide_properties": {
                    "cryptocurrency": False,
                    "has_phonenumbers": False,
                },
                "smali_properties": {
                    "record_screen": False,
                    "set_component": False,
                    "cookie_manager": False,
                    "execute_native": False,
                    "intent_chooser": False,
                    "open_non_asset": False,
                    "package_delete": False,
                    "perform_action": False,
                    "abort_broadcast": False,
                    "get_line_number": False,
                    "package_session": False,
                    "check_permission": False,
                },
                "sanitized_basename": "sample3.apk",
                "manifest_properties": {
                    "swf": False,
                    "maxSDK": None,
                    "minSDK": None,
                    "services": [],
                    "libraries": [],
                    "providers": [],
                    "receivers": [],
                    "targetSDK": None,
                    "activities": ["'ph0wn.ctf.playfrequency.MainActivity'"],
                    "permissions": [],
                    "package_name": "ph0wn.ctf.playfrequency",
                    "main_activity": "ph0wn.ctf.playfrequency.MainActivity",
                    "listens_incoming_sms": False,
                    "listens_outgoing_call": False,
                },
            },
            200,
        )
