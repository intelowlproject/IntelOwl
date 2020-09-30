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


@shared_task(soft_time_limit=30)
def abuseipdb_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    abuseipdb.AbuseIPDB(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def auth0_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    auth0.Auth0(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def securitytrails_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    securitytrails.SecurityTrails(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def activedns_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    active_dns.ActiveDNS(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def fortiguard_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    fortiguard.Fortiguard(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def greynoise_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    greynoise.GreyNoise(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def googlesf_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    googlesf.GoogleSF(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def otx_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    otx.OTX(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def misp_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    misp.MISP(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def circlpdns_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    circl_pdns.CIRCL_PDNS(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def circlpssl_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    circl_pssl.CIRCL_PSSL(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def robtex_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    robtex.Robtex(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def shodan_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    shodan.Shodan(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def threatminer_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    threatminer.Threatminer(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def hunter_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    hunter.Hunter(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def censys_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    censys.Censys(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def dnsdb_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    dnsdb.DNSdb(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def maxmind_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    maxmind.Maxmind(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=20)
def maxmind_updater():
    maxmind.Maxmind.updater({})


@shared_task(soft_time_limit=30)
def talos_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    talos.Talos(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=60)
def talos_updater():
    talos.Talos.updater()


@shared_task(soft_time_limit=30)
def tor_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    tor.Tor(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=60)
def tor_updater():
    tor.Tor.updater()


@shared_task(soft_time_limit=30)
def vt2get_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    vt2_get.VirusTotalv2(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def haget_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    ha_get.HybridAnalysisGet(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=40)
def vt3get_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    vt3_get.VirusTotalv3(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=500)
def vt3get_scan_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    vt3_get.VirusTotalv3(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=200)
def honeydb_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    honeydb.HoneyDB(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=50)
def onyphe_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    onyphe.Onyphe(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=50)
def urlhaus_run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    urlhaus.URLHaus(
        analyzer_name,
        job_id,
        observable_name,
        observable_classification,
        additional_config_params,
    ).start()


@shared_task(soft_time_limit=30)
def fileinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    file_info.FileInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=70)
def stringsinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    strings_info.StringsInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def signatureinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    signature_info.SignatureInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=120)
def speakeasy_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    speakeasy_emulation.SpeakEasy(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def peinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    pe_info.PEInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def docinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    doc_info.DocInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def rtfinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    rtf_info.RTFInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=30)
def pdfinfo_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    pdf_info.PDFInfo(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=400)
def vt2scan_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    vt2_scan.VirusTotalv2ScanFile(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=500)
def vt3scan_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    vt3_scan.VirusTotalv3ScanFile(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=180)
def intezer_run(
    analyzer_name, job_id, filepath, filename, md5, additional_config_params
):
    intezer_scan.IntezerScan(
        analyzer_name, job_id, filepath, filename, md5, additional_config_params
    ).start()


@shared_task(soft_time_limit=500)
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
