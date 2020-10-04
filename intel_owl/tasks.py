from __future__ import absolute_import, unicode_literals
from celery import shared_task
from api_app.script_analyzers.file_analyzers import (
    doc_info,
    file_info,
    pe_info,
    pdf_info,
    vt2_scan,
    intezer_scan,
    cuckoo_scan,
    yara_scan,
    vt3_scan,
    strings_info,
    rtf_info,
    signature_info,
    speakeasy_emulation,
    peframe,
    thug_file,
    capa_info,
    boxjs_scan,
    apkid,
    quark_engine,
    unpac_me,
    xlm_macro_deobfuscator,
)
from api_app.script_analyzers.observable_analyzers import (
    abuseipdb,
    fortiguard,
    maxmind,
    greynoise,
    googlesf,
    otx,
    talos,
    tor,
    circl_pdns,
    circl_pssl,
    robtex,
    vt2_get,
    ha_get,
    vt3_get,
    misp,
    dnsdb,
    shodan,
    honeydb,
    hunter,
    mb_get,
    onyphe,
    censys,
    threatminer,
    thug_url,
    urlhaus,
    active_dns,
    auth0,
    securitytrails,
    cymru,
    tranco,
    pulsedive,
    intelx,
    whoisxmlapi,
    checkdmarc,
    urlscan,
)

from api_app import crons
from api_app.script_analyzers import observable_analyzers, file_analyzers
from api_app.script_analyzers.classes import BaseAnalyzerMixin
from api_app.script_analyzers.utils import set_report_and_cleanup, set_failed_analyzer
from guardian import utils


@shared_task(soft_time_limit=200)
def clean_orphan_obj_perms():
    utils.clean_orphan_obj_perms()


@shared_task(soft_time_limit=10000)
def remove_old_jobs():
    crons.remove_old_jobs()


@shared_task(soft_time_limit=120)
def check_stuck_analysis():
    crons.check_stuck_analysis()


@shared_task(soft_time_limit=120)
def flush_expired_tokens():
    crons.flush_expired_tokens()


@shared_task(soft_time_limit=500)
<<<<<<< HEAD
def analyzer_run(typ, module_name, *args):
    try:
        modname, clsname = module_name.split(".")

        if typ == "observable":
            mod = getattr(observable_analyzers, modname)
        else:
            mod = getattr(file_analyzers, modname)
        if not mod:
            raise Exception(f"Module: {module_name} couldn't be imported")

        cls: BaseAnalyzerMixin = getattr(mod, clsname)
        if not cls:
            raise Exception(f"Class: {module_name} couldn't be imported")

        instance: BaseAnalyzerMixin = cls(*args)
        instance.start()
        set_report_and_cleanup(
            instance.analyzer_name,
            instance.job_id,
            instance.report,
        )
    except Exception as e:
        set_failed_analyzer(args[0], args[1], str(e))
=======
def cuckoo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    cuckoo_scan.CuckooAnalysis(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=60)
def yara_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    yara_scan.YaraScan(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=60)
def yara_updater():
    yara_scan.YaraScan.yara_update_repos()


@shared_task(soft_time_limit=50)
def mbget_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    mb_get.MB_GET(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=50)
def cymru_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    cymru.Cymru(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def tranco_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    tranco.Tranco(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=100)
def pulsedive_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    pulsedive.Pulsedive(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=100)
def urlscan_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    urlscan.UrlScan(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=45)
def intelx_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    intelx.IntelX(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=500)
def peframe_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    peframe.PEframe(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=500)
def capa_info_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    capa_info.CapaInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=600)
def thug_file_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    thug_file.ThugFile(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=600)
def thug_url_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    thug_url.ThugUrl(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=400)
def boxjs_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    boxjs_scan.BoxJS(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=400)
def apkid_run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    apkid.APKiD(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=120)
def quark_engine_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    quark_engine.QuarkEngine(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=400)
def unpac_me_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    unpac_me.UnpacMe(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def whoisxmlapi_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    whoisxmlapi.Whoisxmlapi(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def checkdmarc_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    checkdmarc.CheckDMARC(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()
>>>>>>> 647f95e0ce075a6c9b0e021ffc3c4f3359eb382d
