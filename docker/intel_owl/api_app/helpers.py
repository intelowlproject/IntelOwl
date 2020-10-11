# general helper functions used by the Django API

import json
import logging
import hashlib
from magic import from_buffer as magic_from_buffer

from django.utils import timezone

from .exceptions import NotRunnableAnalyzer
from api_app import models

logger = logging.getLogger(__name__)


def get_now_date_only():
    return str(timezone.now().date())


def get_now():
    return timezone.now()


def get_analyzer_config():
    with open("/opt/deploy/configuration/analyzer_config.json") as f:
        analyzers_config = json.load(f)
    return analyzers_config


def calculate_mimetype(file_buffer, file_name):
    read_file_buffer = file_buffer.read()
    calculated_mimetype = magic_from_buffer(read_file_buffer, mime=True)
    if file_name:
        if file_name.endswith(".js") or file_name.endswith(".jse"):
            calculated_mimetype = "application/javascript"
        elif file_name.endswith(".vbs") or file_name.endswith(".vbe"):
            calculated_mimetype = "application/x-vbscript"
        elif file_name.endswith(".iqy"):
            calculated_mimetype = "text/x-ms-iqy"
        elif file_name.endswith(".apk"):
            calculated_mimetype = "application/vnd.android.package-archive"
        elif file_name.endswith(".dex"):
            calculated_mimetype = "application/x-dex"

    return calculated_mimetype


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
                if not analyzer_config.get("type", None) == "file":
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
                if not analyzer_config.get("type", None) == "observable":
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
            if analyzer_config.get("disabled", False):
                raise NotRunnableAnalyzer(f"{analyzer} is disabled, won't be run.")
            if serialized_data["force_privacy"] and analyzer_config.get(
                "leaks_info", False
            ):
                raise NotRunnableAnalyzer(
                    f"{analyzer} won't be run because it leaks info externally."
                )
            if serialized_data["disable_external_analyzers"] and analyzer_config.get(
                "external_service", False
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


def get_binary(job_id, job_object=None):
    if not job_object:
        job_object = models.Job.object_by_job_id(job_id)
    logger.info(f"getting binary for job_id {job_id}")
    job_file = job_object.file
    logger.info(f"got job_file {job_file} for job_id {job_id}")

    binary = job_file.read()
    return binary


def generate_sha256(job_id):
    binary = get_binary(job_id)
    return hashlib.sha256(binary).hexdigest()
