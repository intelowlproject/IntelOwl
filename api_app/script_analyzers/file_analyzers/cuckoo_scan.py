import re
import time
import traceback
import requests
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)


class CuckooAnalysis:
    def __init__(self, api_key, cuckoo_url):
        self.cuckoo_url = cuckoo_url
        self.session = requests.Session()
        self.task_id = 0
        self.report = {}
        if api_key:
            self.session.headers['Authorization'] = 'Bearer {}'.format(api_key)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        # cuckoo installation can be with or without the api_token
        # it depends on version and configuration
        api_key_name = additional_config_params.get('api_key_name', '')
        if api_key_name:
            api_key = secrets.get_secret(api_key_name)
        else:
            api_key = None
            logger.info("job_id {} md5 {} analyzer {} no API key set"
                        "".format(job_id, md5, analyzer_name))

        cuckoo_url = secrets.get_secret("CUCKOO_URL")
        if not cuckoo_url:
            raise AnalyzerRunException("cuckoo URL missing")

        cuckoo_analysis = CuckooAnalysis(api_key, cuckoo_url)

        binary = general.get_binary(job_id)
        if not binary:
            raise AnalyzerRunException("is the binary empty?!")
        _cuckoo_scan_file(cuckoo_analysis, additional_config_params, filename, md5, binary)

        result = cuckoo_analysis.report
        # pprint.pprint(result)
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

    return report


def _cuckoo_scan_file(cuckoo_analysis, additional_config_params, filename, md5, binary):

    _cuckoo_request_scan(cuckoo_analysis, additional_config_params, filename, md5, binary)

    _cuckoo_poll_result(cuckoo_analysis, filename, md5, additional_config_params)

    _cuckoo_retrieve_and_create_report(cuckoo_analysis, filename, md5)


def _cuckoo_request_scan(cuckoo_analysis, additional_config_params, filename, md5, binary):
    logger.info("requesting scan for {} {}".format(filename, md5))

    # send the file for analysis
    name_to_send = filename if filename else md5
    files = {"file": (name_to_send, binary)}
    max_post_tries = additional_config_params.get('max_post_tries', 5)
    post_success = False
    response = None
    for chance in range(max_post_tries):
        logger.info("request n.{} for file analysis of {} {}"
                    "".format(chance, filename, md5))
        response = cuckoo_analysis.session.post(cuckoo_analysis.cuckoo_url + 'tasks/create/file', files=files)
        if response.status_code != 200:
            logger.info("failed post to start cuckoo analysis, status code {}"
                        "".format(response.status_code))
            time.sleep(5)
            continue
        else:
            post_success = True
            break

    if post_success:
        json_response = response.json()
        cuckoo_analysis.task_id = json_response['task_ids'][0] if 'task_ids' in json_response.keys()\
            else json_response.get('task_id', 1)
    else:
        raise AnalyzerRunException("failed max tries to post file to cuckoo for analysis")


def _cuckoo_poll_result(cuckoo_analysis, filename, md5, additional_config_params):
    logger.info("polling result for {} {}, task_id {}".format(filename, md5, cuckoo_analysis.task_id))

    # poll for the result
    max_get_tries = additional_config_params.get('max_poll_tries', 50)
    poll_time = 15
    get_success = False
    for chance in range(max_get_tries):
        logger.info("polling request n.{} for file {} {}"
                    "".format(chance+1, filename, md5))
        url = cuckoo_analysis.cuckoo_url + 'tasks/view/' + str(cuckoo_analysis.task_id)
        response = cuckoo_analysis.session.get(url)
        json_response = response.json()
        status = json_response.get('task', {}).get('status', '')
        if status == 'reported':
            get_success = True
            break
        elif status == 'failed_processing':
            raise AnalyzerRunException("sandbox analysis failed. cuckoo id: {} status 'failed_processing'"
                                       "".format(cuckoo_analysis.task_id))
        else:
            time.sleep(poll_time)

    if not get_success:
        raise AnalyzerRunException("sandbox analysis timed out. cuckoo id: {}"
                                   "".format(cuckoo_analysis.task_id))


def _cuckoo_retrieve_and_create_report(cuckoo_analysis, filename, md5):
    logger.info("generating report for {} {}, task_id {}".format(filename, md5, cuckoo_analysis.task_id))
    # download the report
    response = cuckoo_analysis.session.get(cuckoo_analysis.cuckoo_url + 'tasks/report/'
                                           + str(cuckoo_analysis.task_id) + '/json')
    json_response = response.json()

    # extract most IOCs as possibile from signatures data reports
    signatures = json_response.get('signatures', [])
    list_description_signatures = []
    list_detailed_signatures = []
    list_potentially_malicious_urls_marks = []
    list_dyndns_domains_marks = []
    list_potentially_malicious_urls = []
    regex_url = re.compile('((?:(?:ht|f)tp(?:s?)\:\/\/)(?:[!#$&-;=?-\[\]_a-z~]|%[0-9a-f]{2})+)(?![\)])', re.I)
    for sig in signatures:
        sig_description = sig.get('description', '')
        sig_name = sig.get('name', '')
        sig_severity = sig.get('severity', '')
        sig_marks = sig.get('marks', [])
        list_description_signatures.append(sig_description)
        detailed_signature_data = {
            'description':  sig_description,
            'name': sig_name,
            'severity': sig_severity,
            'marks': sig_marks
        }
        list_detailed_signatures.append(detailed_signature_data)
        # get URL marks from some specific signatures
        if 'malicious URL found' in sig_description or 'External resource URLs' in sig_description \
                or 'Powershell script' in sig_description:
            list_potentially_malicious_urls_marks.extend(sig_marks)
        # get dydns domains from the specific signature
        if 'networkdyndns_checkip' in sig_name:
            list_dyndns_domains_marks.extend(sig_marks)
        # look for IOCs extracted from specific signatures
        if 'suspicious_process' in sig_name:
            for suspicious_process_mark in sig_marks:
                suspicious_process_ioc = suspicious_process_mark.get('ioc', '')
                match_url = re.search(regex_url, suspicious_process_ioc)
                if match_url:
                    list_potentially_malicious_urls.append(match_url.group(1))

    # extract dyndns domains from specific signature, could be IOCs
    dyndns_domains = []
    for mark in list_dyndns_domains_marks:
        dydns_ioc = mark.get('ioc', '')
        dyndns_domains.append(dydns_ioc)

    # parse specific signatures
    for mark in list_potentially_malicious_urls_marks:
        ioc = mark.get('ioc', '')
        if ioc and ioc.startswith("http"):
            list_potentially_malicious_urls.append(ioc)
        if mark.get('config', {}):
            if mark['config'].get('url', []):
                list_potentially_malicious_urls.extend(mark['config']['url'])

    # remove duplicates
    list_potentially_malicious_urls = list(set(list_potentially_malicious_urls))

    # get suricata alerts if available
    suricata_alerts = [alert for alert in json_response.get('suricata', {}).get('alerts', [])]

    # get network data
    network_data = json_response.get('network', {})
    uri = [(network['uri']) for network in network_data.get('http', [])]
    domains = [{'ip': network['ip'], 'domain': network['domain']} for network in network_data.get('domains', [])]

    # extract all dns domain requested, can be used as IOC even if the conn was not successful
    dns_answered_list = []
    dns_data = network_data.get('dns', {})
    for dns_dict in dns_data:
        # if there are A records and we received an answer
        if dns_dict.get('type', '') == "A" and dns_dict.get('answers', []) and dns_dict.get('request', ''):
            dns_answered_list.append(dns_dict['request'])

    # other info
    info_data = json_response.get('info', {})
    # cuckoo magic score
    cuckoo_score = info_data.get('score', None)
    machine_data = info_data.get('machine', {})
    new_stats = info_data.get('new_stats', None)
    cuckoo_id = info_data.get('id', '')
    malfamily = json_response.get('malfamily', None)
    static = json_response.get('static', {})
    behavior = json_response.get('behavior', {})
    generic_behavior = behavior.get('generic', {})
    api_stats = behavior.get('apistats', {})
    extracted = json_response.get('extracted', {})
    processtree = behavior.get('processtree', {})
    anomaly = behavior.get('anomaly', {})
    debug = json_response.get('debug', {})
    file_data = json_response.get('target', {}).get('file', {})
    file_type = ''.join([f_type for f_type in file_data.get('type', '')])
    yara = [yara_match['name'] for yara_match in file_data.get('yara', [])]

    result = {
        'signatures': list_description_signatures,
        'signatures_detailed': list_detailed_signatures,
        'suricata_alerts': suricata_alerts,
        'potentially_malicious_urls': list_potentially_malicious_urls,
        'dyndns_domains': dyndns_domains,
        'answered_dns': dns_answered_list,
        'domains': domains,
        'uri': uri,
        'malscore': cuckoo_score,
        'malfamily': malfamily,
        'new_stats': new_stats,
        'file_type': file_type,
        'machine': machine_data,
        'id': cuckoo_id,
        'debug': debug,
        'yara': yara,
        'static': static,
        'behavior': {
            'generic_behavior': generic_behavior,
            'api_stats': api_stats,
            'extracted': extracted,
            'processtree': processtree,
            'anomaly': anomaly
        }
    }

    logger.info("report generated for {} {}".format(filename, md5))

    cuckoo_analysis.report = result


