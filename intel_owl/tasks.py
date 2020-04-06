from __future__ import absolute_import, unicode_literals

from celery import shared_task
from api_app.script_analyzers.file_analyzers import doc_info, file_info, pe_info, pdf_info, vt2_scan, intezer_scan, \
    cuckoo_scan, yara_scan, vt3_scan, strings_info, rtf_info, signature_info
from api_app.script_analyzers.observable_analyzers import abuseipdb, fortiguard, maxmind, greynoise, googlesf, otx, \
    talos, tor, circl_pdns, circl_pssl, robtex, vt2_get, ha_get, vt3_get, misp, dnsdb, \
    shodan, honeydb, hunter, mb_get, onyphe, censys, threatminer, urlhaus, active_dns

from api_app import crons


@shared_task(soft_time_limit=500)
def remove_old_jobs():
    crons.remove_old_jobs()


@shared_task(soft_time_limit=120)
def check_stuck_analysis():
    crons.check_stuck_analysis()


@shared_task(soft_time_limit=30)
def abuseipdb_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    abuseipdb.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def activedns_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    active_dns.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def fortiguard_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    fortiguard.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def greynoise_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    greynoise.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def googlesf_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    googlesf.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def otx_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    otx.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def misp_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    misp.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def circlpdns_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    circl_pdns.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def circlpssl_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    circl_pssl.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def robtex_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    robtex.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def shodan_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    shodan.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def threatminer_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    threatminer.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def hunter_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    hunter.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def censys_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    censys.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def dnsdb_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    dnsdb.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def maxmind_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    maxmind.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=20)
def maxmind_updater():
    maxmind.updater({})


@shared_task(soft_time_limit=30)
def talos_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    talos.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=60)
def talos_updater():
    talos.updater()


@shared_task(soft_time_limit=30)
def tor_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    tor.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=60)
def tor_updater():
    tor.updater()


@shared_task(soft_time_limit=30)
def vt2get_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    vt2_get.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def haget_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    ha_get.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=40)
def vt3get_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    vt3_get.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=500)
def vt3get_scan_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    vt3_get.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=200)
def honeydb_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    honeydb.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=50)
def onyphe_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    onyphe.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=50)
def urlhaus_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    urlhaus.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)


@shared_task(soft_time_limit=30)
def fileinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    file_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=70)
def stringsinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    strings_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=30)
def signatureinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    signature_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=30)
def peinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    pe_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=30)
def docinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    doc_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=30)
def rtfinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    rtf_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=30)
def pdfinfo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    pdf_info.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=400)
def vt2scan_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    vt2_scan.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=500)
def vt3scan_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    vt3_scan.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=180)
def intezer_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    intezer_scan.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=500)
def cuckoo_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    cuckoo_scan.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=60)
def yara_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    yara_scan.run(analyzer_name, job_id, filepath, filename, md5, additional_config_params)


@shared_task(soft_time_limit=60)
def yara_updater():
    yara_scan.yara_update_repos()


@shared_task(soft_time_limit=50)
def mbget_run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    mb_get.run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params)