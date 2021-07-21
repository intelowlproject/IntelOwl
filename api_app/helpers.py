# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import json
import logging
import hashlib
from magic import from_buffer as magic_from_buffer

from django.utils import timezone

from . import models

logger = logging.getLogger(__name__)


def get_now_date_only():
    return str(timezone.now().date())


def get_now():
    return timezone.now()


def get_analyzer_config():
    with open("/opt/deploy/configuration/analyzer_config.json") as f:
        analyzers_config = json.load(f)
    return analyzers_config


def calculate_mimetype(file_pointer, file_name) -> str:
    mimetype = None
    if file_name:
        if file_name.endswith(".js") or file_name.endswith(".jse"):
            mimetype = "application/javascript"
        elif file_name.endswith(".vbs") or file_name.endswith(".vbe"):
            mimetype = "application/x-vbscript"
        elif file_name.endswith(".iqy"):
            mimetype = "text/x-ms-iqy"
        elif file_name.endswith(".apk"):
            mimetype = "application/vnd.android.package-archive"
        elif file_name.endswith(".dex"):
            mimetype = "application/x-dex"

    if not mimetype:
        buffer = file_pointer.read()
        mimetype = magic_from_buffer(buffer, mime=True)

    return mimetype


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
