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
    return 'job_{}_{}'.format(get_now_str(), filename)


def filter_analyzers(serialized_data, analyzers_requested, analyzers_config, warnings, run_all=False):
    cleaned_analyzer_list = []
    for analyzer in analyzers_requested:
        try:
            if analyzer not in analyzers_config:
                raise NotRunnableAnalyzer("{} not available in configuration".format(analyzer))
            if serialized_data['is_sample']:
                if not analyzers_config[analyzer].get('type', '') == 'file':
                    raise NotRunnableAnalyzer("{} won't be run because does not support files".format(analyzer))
                if analyzers_config[analyzer].get('supported_filetypes', []) and \
                        serialized_data['file_mimetype'] not in analyzers_config[analyzer]['supported_filetypes']:
                    raise_message = "{} won't be run because mimetype {} is not supported. Supported are:{}" \
                                    "".format(analyzer, serialized_data['file_mimetype'], analyzers_config[analyzer]['supported_filetypes'])
                    raise NotRunnableAnalyzer(raise_message)
                if analyzers_config[analyzer].get('not_supported_filetypes', '') and \
                        serialized_data['file_mimetype'] in analyzers_config[analyzer]['not_supported_filetypes']:
                    raise_message = "{} won't be run because mimetype {} is not supported. Not supported are:{}" \
                                    "".format(analyzer, serialized_data['file_mimetype'], analyzers_config[analyzer]['not_supported_filetypes'])
                    raise NotRunnableAnalyzer(raise_message)
            else:
                if not analyzers_config[analyzer].get('type', '') == 'observable':
                    raise NotRunnableAnalyzer("{} won't be run because does not support observable".format(analyzer))
                if serialized_data['observable_classification'] not in \
                        analyzers_config[analyzer].get('observable_supported', []):
                    raise NotRunnableAnalyzer("{} won't be run because does not support observable type {}"
                                              "".format(analyzer, serialized_data['observable_classification']))
            if analyzers_config[analyzer].get('disabled', ''):
                raise NotRunnableAnalyzer("{} is disabled, won't be run".format(analyzer))
            if serialized_data['force_privacy'] and analyzers_config[analyzer].get('leaks_info', ''):
                raise NotRunnableAnalyzer("{} won't be run because it leaks info externally".format(analyzer))
            if serialized_data['disable_external_analyzers'] and analyzers_config[analyzer].get('external_service', ''):
                raise NotRunnableAnalyzer("{} won't be run because you filtered external analyzers".format(analyzer))
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
