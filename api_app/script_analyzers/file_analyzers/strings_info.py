import logging
from subprocess import Popen, DEVNULL, PIPE

from celery.exceptions import SoftTimeLimitExceeded

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


logger = logging.getLogger(__name__)


class StringsInfo(classes.FileAnalyzer):
    def set_config(self, additional_config_params):
        self.max_no_of_strings = int(
            additional_config_params.get("max_number_of_strings", 500)
        )
        self.max_chars_for_string = int(
            additional_config_params.get("max_characters_for_string", 1000)
        )

        # If set, this module will use Machine Learning feature
        # CARE!! ranked_strings could be cpu/ram intensive and very slow
        self.rank_strings = additional_config_params.get("rank_strings", False)

    def run(self):
        p1 = None
        p2 = None
        try:
            results = {}
            # this is brutal, to resolve this with a proper library when available
            flare_command = ["flarestrings", self.filepath]
            p1 = Popen(flare_command, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
            if self.rank_strings:
                rank_command = ["rank_strings", "-l", str(self.max_no_of_strings)]
                p2 = Popen(rank_command, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
                out, err = p2.communicate()
                output_rankstrings = out.decode()

                if p2.returncode != 0:
                    raise AnalyzerRunException(
                        f"rank_strings return code is {p2.returncode}. Error: {err}"
                    )
                if len(output_rankstrings) == self.max_no_of_strings:
                    results["exceeded_max_number_of_strings"] = True
                results["ranked_strings"] = [
                    s[: self.max_chars_for_string]
                    for s in output_rankstrings.split("\n")
                ]

            else:
                out, err = p1.communicate()
                output_flarestrings = out.decode()

                if p1.returncode != 0:
                    raise AnalyzerRunException(
                        f"flarestrings return code is {p1.returncode}. Error: {err}"
                    )
                if len(output_flarestrings) >= self.max_no_of_strings:
                    results["exceeded_max_number_of_strings"] = True
                results["flare_strings"] = [
                    s[: self.max_chars_for_string]
                    for s in output_flarestrings.split("\n")[: self.max_no_of_strings]
                ]

        except SoftTimeLimitExceeded as e:
            error_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} md5:{self.md5}"
                f"filename:{self.filename}. Soft Time Limit Exceeded Error: {e}"
            )
            logger.error(error_message)
            self.report["errors"].append(str(e))
            self.report["success"] = False
            # we should stop the subprocesses...
            # .. in case we reach the time limit for the celery task
            if p1:
                p1.kill()
            if p2:
                p2.kill()

        return results
