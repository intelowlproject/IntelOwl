from django.contrib.postgres import fields as pg_fields
from django.db import models


class IETFReport(models.Model):
    rrname = models.CharField(max_length=100)
    rrtype = models.CharField(max_length=100)
    rdata = pg_fields.ArrayField(models.CharField(max_length=100))
    time_first = models.DateTimeField()
    time_last = models.DateTimeField()


class DomainDataModel(models.Model):
    evaluation = models.CharField(max_length=100, null=True)
    classification = models.CharField(
        max_length=100,
        null=True,
    )  # HybridAnalysisObservable (verdict), BasicMaliciousDetector,
    # GoogleSafeBrowsing, Crowdsec
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    tranco_rank = models.IntegerField(null=True)  # Tranco
    related_url = models.URLField(
        null=True
    )  # Crowdsec (link), UrlHaus (external_references)
    threats = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # GoogleSafeBrowsing


class IPDataModel(models.Model):
    evaluation = models.CharField(max_length=100, null=True)
    classification = models.CharField(
        max_length=100,
        null=True,
    )  # Crowdsec, GreyNoise, HybridAnalysisObservable (verdict),
    # BasicMaliciousDetector, GoogleSafeBrowsing
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    asn = models.IntegerField(null=True)  # BGPRanking, MaxMind
    asn_rank = models.DecimalField(null=True)  # BGPRanking
    certificates = models.JSONField(null=True)  # CIRCL_PSSL
    behavior = models.CharField(max_length=100, null=True)  # Crowdsec
    related_urls = pg_fields.ArrayField(
        models.URLField(), null=True
    )  # Crowdsec (link), UrlHaus (external_references)
    noise = models.BooleanField(null=True)  # GreyNoise
    riot = models.BooleanField(null=True)  # GreyNoise
    org_name = models.CharField(max_length=100, null=True)  # GreyNoise
    vx_family = models.CharField(max_length=100, null=True)  # HybridAnalysisObservable
    country = models.CharField(max_length=100, null=True)  # MaxMind, AbuseIPDB
    country_code = models.CharField(max_length=100, null=True)  # MaxMind, AbuseIPDB
    registered_country = models.CharField(
        max_length=100, null=True
    )  # MaxMind, AbuseIPDB
    registered_country_code = models.CharField(
        max_length=100, null=True
    )  # MaxMind, AbuseIPDB
    isp = models.CharField(max_length=100, null=True)  # AbuseIPDB
    threats = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # GoogleSafeBrowsing
    is_anonymizer = models.BooleanField(null=True)  # TorProject, Crowdsec
    is_tor_exit_node = models.BooleanField(null=True)  # TorProject, Crowdsec


class FileDataModel(models.Model):
    evaluation = models.CharField(
        max_length=100,
        null=True,
    )  # Cymru (found), Cuckoo (malscore), Intezer (verdict/sub_verdict),
    # Triage (analysis.score)
    classification_tags = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # HybridAnalysisFileAnalyzer
    tags = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # HybridAnalysisFileAnalyzer, MalwareBazaarFileAnalyzer, MwDB,
    # VirusTotalV3FileAnalyzer (report.data.tags)
    compromised_hosts = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # HybridAnalysisFileAnalyzer
    related_urls = pg_fields.ArrayField(
        models.URLField(), null=True
    )  # Crowdsec (link), UrlHaus (external_references), BoxJs,
    # Cuckoo (result_url/permalink), Intezer (link/analysis_url),
    # MalwareBazaarFileAnalyzer (permalink/file_information.value), MwDB (permalink),
    # StringsInfo (data), Triage (permalink), UnpacMe (permalink), XlmMacroDeobfuscator,
    # Yara (report.list_el.url/rule_url), Yaraify (link),
    # HybridAnalysisFileAnalyzer (domains),
    # VirusTotalV3FileAnalyzer (data.relationships.contacted_urls/contacted_domains)
    signatures = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # ClamAvFileAnalyzer, MalwareBazaarFileAnalyzer, Yara (report.list_el.match)
    family = models.CharField(
        max_length=100,
        null=True,
    )  # Intezer (family_name), Cuckoo, MwDB, Triage (analysis.family),
    # UnpacMe (results.malware_id.malware_family),
    # VirusTotalV3FileAnalyzer
    # (attributes.last_analysis_results.list_el.results/attributes.names)
    yara_rules = pg_fields.ArrayField(
        models.JSONField(), null=True
    )  # MalwareBazaarFileAnalyzer, Yaraify (report.data.tasks.static_result)
    comments = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # MalwareBazaarFileAnalyzer,
    # VirusTotalV3FileAnalyzer (data.relationships.comments)
    file_information = pg_fields.ArrayField(
        models.JSONField(), null=True
    )  # MalwareBazaarFileAnalyzer, OneNoteInfo
    # (files), QuarkEngineAPK (crimes.confidence, threat_level, total_score)
    # RtfInfo (exploit_equation_editor, exploit_ole2link_vuln)
    related_threats = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # MalwareBazaarFileAnalyzer(?), QuarkEngineAPK (crimes.crime)
    stats = pg_fields.ArrayField(
        models.JSONField(), null=True
    )  # PdfInfo (peepdf_stats)
    pdfid_reports = pg_fields.ArrayField(models.JSONField(), null=True)  # PdfInfo
    imphash = models.CharField(max_length=100, null=True)  # PeInfo
    type = models.CharField(max_length=100, null=True)  # PeInfo
