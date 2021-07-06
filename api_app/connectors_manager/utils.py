# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.models import Job


logger = logging.getLogger(__name__)


def set_failed_connector(connector_name, job_id, err_msg):
    logger.warning(
        f"({connector_name}, job_id #{job_id}) -> set as FAILED. "
        f" Error message: {err_msg}"
    )

    report = Job.init_connector_report(connector_name, job_id)
    report.errors.append(err_msg)
    report.save()
