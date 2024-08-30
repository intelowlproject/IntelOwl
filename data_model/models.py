from django.contrib.postgres import fields as pg_fields
from django.db import models

from data_model.enums import DataModelTags, SignaturesChoices


class IETFReport(models.Model):
    rrname = models.CharField(max_length=100)
    rrtype = models.CharField(max_length=100)
    rdata = pg_fields.ArrayField(models.CharField(max_length=100))
    time_first = models.DateTimeField()
    time_last = models.DateTimeField()


class Signature(models.Model):
    name = models.CharField(max_length=100)
    SIGNATURES = SignaturesChoices
    signature = models.JSONField()


class BaseDataModel(models.Model):
    evaluation = models.CharField(
        max_length=100, null=True
    )  # classification/verdict/found/score/malscore
    # HybridAnalysisObservable (verdict), BasicMaliciousDetector (malicious),
    # GoogleSafeBrowsing (malicious), Crowdsec (classifications),
    # GreyNoise (classification), Cymru (found), Cuckoo (malscore),
    # Intezer (verdict/sub_verdict), Triage (analysis.score),
    # HybridAnalysisFileAnalyzer (classification_tags)
    external_references = pg_fields.ArrayField(
        models.URLField(),
        blank=True,
        default=list,
    )  # link/external_references/permalink/domains
    # Crowdsec (link), UrlHaus (external_references), BoxJs,
    # Cuckoo (result_url/permalink), Intezer (link/analysis_url),
    # MalwareBazaarFileAnalyzer (permalink/file_information.value), MwDB (permalink),
    # StringsInfo (data), Triage (permalink), UnpacMe (permalink), XlmMacroDeobfuscator,
    # Yara (report.list_el.url/rule_url), Yaraify (link),
    # HybridAnalysisFileAnalyzer (domains),
    # VirusTotalV3FileAnalyzer (data.relationships.contacted_urls/contacted_domains)
    related_threats = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # threats/related_threats, used as a pointer to other IOCs
    tags = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # used for generic tags like phishing, malware, social_engineering
    # HybridAnalysisFileAnalyzer, MalwareBazaarFileAnalyzer, MwDB,
    # VirusTotalV3FileAnalyzer (report.data.attributes.tags)
    # GoogleSafeBrowsing, QuarkEngineAPK (crimes.crime)
    TAGS = DataModelTags
    malware_family = models.CharField(
        max_length=100, null=True
    )  # family/family_name/malware_family
    # HybridAnalysisObservable, Intezer (family_name), Cuckoo, MwDB,
    # Triage (analysis.family), UnpacMe (results.malware_id.malware_family),
    # VirusTotalV3FileAnalyzer
    # (attributes.last_analysis_results.list_el.results/attributes.names)
    additional_info = (
        models.JSONField()
    )  # field for additional information related to a specific analyzer


class DomainDataModel(BaseDataModel):
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    rank = models.IntegerField(null=True)  # Tranco


class IPDataModel(BaseDataModel):
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    asn = models.IntegerField(null=True)  # BGPRanking, MaxMind
    asn_rank = models.DecimalField(null=True)  # BGPRanking
    certificates = models.JSONField(null=True)  # CIRCL_PSSL
    org_name = models.CharField(max_length=100, null=True)  # GreyNoise
    country = models.CharField(max_length=100, null=True)  # MaxMind, AbuseIPDB
    country_code = models.CharField(max_length=100, null=True)  # MaxMind, AbuseIPDB
    registered_country = models.CharField(
        max_length=100, null=True
    )  # MaxMind, AbuseIPDB
    registered_country_code = models.CharField(
        max_length=100, null=True
    )  # MaxMind, AbuseIPDB
    isp = models.CharField(max_length=100, null=True)  # AbuseIPDB
    # additional_info
    # behavior = models.CharField(max_length=100, null=True)  # Crowdsec
    # noise = models.BooleanField(null=True)  # GreyNoise
    # riot = models.BooleanField(null=True)  # GreyNoise


class FileDataModel(BaseDataModel):
    signatures = models.ManyToManyField(Signature)  # ClamAvFileAnalyzer,
    # MalwareBazaarFileAnalyzer (signatures/yara_rules), Yara (report.list_el.match)
    # Yaraify (report.data.tasks.static_result)
    comments = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True
    )  # MalwareBazaarFileAnalyzer,
    # VirusTotalV3FileAnalyzer (data.relationships.comments)
    file_information = models.JSONField(
        null=True
    )  # MalwareBazaarFileAnalyzer, OneNoteInfo (files),
    # QuarkEngineAPK (crimes.confidence, threat_level, total_score)
    # RtfInfo (exploit_equation_editor, exploit_ole2link_vuln)
    stats = models.JSONField(null=True)  # PdfInfo (peepdf_stats)
    # additional_info
    # compromised_hosts = pg_fields.ArrayField(
    #   models.CharField(max_length=100), null=True
    # )  # HybridAnalysisFileAnalyzer
    # pdfid_reports = models.JSONField(null=True)  # PdfInfo
    # imphash = models.CharField(max_length=100, null=True)  # PeInfo
    # type = models.CharField(max_length=100, null=True)  # PeInfo
