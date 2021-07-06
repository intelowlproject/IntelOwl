# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import transaction
import logging

from ..exceptions import (
    ConnectorConfigurationException,
    ConnectorRunException,
)
from .utils import (
    set_failed_connector,
)
from ..connectors_manager.serializers import ConnectorConfigSerializer
from ..models import Job
from intel_owl.settings import CELERY_QUEUES
from intel_owl.celery import app as celery_app


logger = logging.getLogger(__name__)


def start_connectors(job_id):

    connectors_config = ConnectorConfigSerializer.read_and_verify_config()
    job_object: Job = Job.object_by_job_id(job_id)

    for connector, cc in connectors_config.items():
        if cc["disabled"] or not cc["verification"]["configured"]:
            # if disabled or unconfigured
            break
        try:
            module = cc.get("python_module", None)
            if not module:
                raise ConnectorConfigurationException(
                    f"no python_module available in config for {connector} connector?!"  # noqa: E501
                )

            # Get connector config and secrets
            config_params = cc.get("config", {})
            secret_params = cc.get("secrets", {})
            additional_config_params = {}

            # Creating additional_config_parmas
            # Adding all secrets
            for name, conf in secret_params.items():
                additional_config_params[name] = conf.get("env_var_key", "")

            # Adding all config parameters
            for key, value in config_params.items():
                additional_config_params[key] = value

            # get celery queue
            queue = config_params.get("queue", "default")
            if queue not in CELERY_QUEUES:
                logger.error(
                    f"Connector {connector} has a wrong queue." f" Setting to default"
                )
                queue = "default"

            # construct arguments
            args = [
                f"connectors.{module}",
                connector,
                job_id,
                additional_config_params,
            ]
            # run analyzer with a celery task asynchronously
            stl = config_params.get("soft_time_limit", 300)
            # update Job model with requested connector
            with transaction.atomic():
                job_object.connectors_to_execute.append(connector)
                job_object.save()
            # fire celery task to run connector
            celery_app.send_task(
                "run_connector",
                args=args,
                queue=queue,
                soft_time_limit=stl,
            )

        except (ConnectorConfigurationException, ConnectorRunException) as e:
            err_msg = f"({connector}, job_id #{job_id}) -> Error: {e}"
            logger.error(err_msg)
            set_failed_connector(connector, job_id, err_msg)
