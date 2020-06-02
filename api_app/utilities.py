# general utilities used by the Django App

import json
import logging

from django.utils import timezone

from api_app.exceptions import NotRunnableAnalyzer


logger = logging.getLogger(__name__)


def get_now_date_only():
    return str(timezone.now().date())


def get_now():
    return timezone.now()


def get_now_str():
    return timezone.now().strftime("%Y_%m_%d_%H_%M_%S")


def get_analyzer_config():
    with open("/opt/deploy/configuration/analyzer_config.json") as f:
        analyzers_config = json.load(f)
    return analyzers_config


def file_directory_path(instance, filename):
    return f"job_{get_now_str()}_{filename}"


def filter_analyzers(
    serialized_data, analyzers_requested, analyzers_config, warnings, run_all=False
):
    cleaned_analyzer_list = []
    for analyzer in analyzers_requested:
        try:
            if analyzer not in analyzers_config:
                raise NotRunnableAnalyzer(f"{analyzer} not available in configuration.")

            analyzer_config = analyzers_config[analyzer]

            if serialized_data["is_sample"]:
                if not analyzer_config.get("type", "") == "file":
                    raise NotRunnableAnalyzer(
                        f"{analyzer} won't be run because does not support files."
                    )
                if (
                    analyzer_config.get("supported_filetypes", [])
                    and serialized_data["file_mimetype"]
                    not in analyzer_config["supported_filetypes"]
                ):
                    raise_message = (
                        f"{analyzer} won't be run because mimetype."
                        f"{serialized_data['file_mimetype']} is not supported."
                        f"Supported are:"
                        f"{analyzer_config['supported_filetypes']}."
                    )
                    raise NotRunnableAnalyzer(raise_message)
                if (
                    analyzer_config.get("not_supported_filetypes", "")
                    and serialized_data["file_mimetype"]
                    in analyzer_config["not_supported_filetypes"]
                ):
                    raise_message = f"""
                        {analyzer} won't be run because mimetype
                        {serialized_data['file_mimetype']} is not supported.
                        Not supported are:{analyzer_config['not_supported_filetypes']}.
                    """
                    raise NotRunnableAnalyzer(raise_message)
            else:
                if not analyzer_config.get("type", "") == "observable":
                    raise NotRunnableAnalyzer(
                        f"{analyzer} won't be run because does not support observable."
                    )
                if serialized_data[
                    "observable_classification"
                ] not in analyzer_config.get("observable_supported", []):
                    raise NotRunnableAnalyzer(
                        f"""
                        {analyzer} won't be run because does not support
                         observable type {serialized_data['observable_classification']}.
                        """
                    )
            if analyzer_config.get("disabled", ""):
                raise NotRunnableAnalyzer(f"{analyzer} is disabled, won't be run.")
            if serialized_data["force_privacy"] and analyzer_config.get(
                "leaks_info", ""
            ):
                raise NotRunnableAnalyzer(
                    f"{analyzer} won't be run because it leaks info externally."
                )
            if serialized_data["disable_external_analyzers"] and analyzer_config.get(
                "external_service", ""
            ):
                raise NotRunnableAnalyzer(
                    f"{analyzer} won't be run because you filtered external analyzers."
                )
        except NotRunnableAnalyzer as e:
            if run_all:
                # in this case, they are not warnings but excepted and wanted behavior
                logger.debug(e)
            else:
                logger.warning(e)
                warnings.append(str(e))
        else:
            cleaned_analyzer_list.append(analyzer)

    return cleaned_analyzer_list
