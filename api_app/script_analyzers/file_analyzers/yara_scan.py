import os
import logging
import traceback
import yara

from git import Repo

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from api_app import utilities

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        directories_with_rules = additional_config_params.get('directories_with_rules', [])

        ruleset = []

        for rulepath in directories_with_rules:
            # you should add a "index.yar" or "index.yas" file and select only the rules you would like to run
            if os.path.isdir(rulepath):
                if os.path.isfile(rulepath + '/index.yas'):
                    ruleset.append(yara.load(rulepath + '/index.yas'))
                elif os.path.isfile(rulepath + '/index.yar'):
                    ruleset.append(yara.compile(rulepath + '/index.yar', externals={'filename': filename}))
                else:  # if you do not have an index file, just extract all the rules in the yar files
                    for f in os.listdir(rulepath):
                        full_path = "{}/{}".format(rulepath, f)
                        if os.path.isfile(full_path):
                            if full_path.endswith('.yar'):
                                ruleset.append(yara.compile(full_path, externals={'filename': filename}))
                            elif full_path.endswith('.yas'):
                                ruleset.append(yara.load(full_path))

        if not ruleset:
            raise AnalyzerRunException("there are no rules installed")

        result = []
        for rule in ruleset:
            matches = rule.match(filepath)
            for match in matches:
                # limited to 20 strings reasons because it could be a very long list
                result.append({'match': str(match),
                               'strings': str(match.strings[:20]) if match else '',
                               'tags': match.tags,
                               'meta': match.meta})

        report['report'] = result
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    # pprint.pprint(report)

    return report


def yara_update_repos():
    logger.info("started pulling images from yara public repos")
    analyzer_config = utilities.get_analyzer_config()
    found_yara_dirs = []
    for analyzer_name, analyzer_config in analyzer_config.items():
        if analyzer_name.startswith('Yara_Scan'):
            yara_dirs = analyzer_config.get('additional_config_params', {}).get('git_repo_main_dir', [])
            if not yara_dirs:
                # fall back to required key
                yara_dirs = analyzer_config.get('additional_config_params', {}).get('directories_with_rules', [])
                found_yara_dirs.extend(yara_dirs)
            # customize it as you wish
            for yara_dir in yara_dirs:
                if os.path.isdir(yara_dir):
                    repo = Repo(yara_dir)
                    o = repo.remotes.origin
                    o.pull()
                    logger.info("pull repo on {} dir".format(yara_dir))
                else:
                    logger.warning("yara dir {} does not exist".format(yara_dir))

    return found_yara_dirs
