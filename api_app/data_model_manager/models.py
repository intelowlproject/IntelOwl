import json
from typing import Dict

from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.utils.timezone import now

from api_app.data_model_manager.enums import DataModelTags, SignatureProviderChoices, DataModelEvaluations
from certego_saas.apps.user.models import User


class IETFReport(models.Model):
    rrname = models.CharField(max_length=100)
    rrtype = models.CharField(max_length=100)
    rdata = pg_fields.ArrayField(models.CharField(max_length=100))
    time_first = models.DateTimeField()
    time_last = models.DateTimeField()

    class Meta:
        unique_together = ("rrname", "rrtype", "rdata")

    def __str__(self):
        return json.dumps(
            {
                "rrname": self.rrname,
                "rrtype": self.rrtype,
                "rdata": self.rdata,
                "time_first": self.time_first.strftime("%Y-%m-%d %H:%M:%S"),
                "time_last": self.time_last.strftime("%Y-%m-%d %H:%M:%S")
            }
        )

class Signature(models.Model):
    provider = models.CharField(max_length=100)
    signature = models.JSONField()

    PROVIDERS = SignatureProviderChoices

    def __str__(self):
        return f"{self.provider}: {json.dumps(self.signature)}"



class BaseDataModel(models.Model):
    analyzer_report = models.OneToOneField(
        "analyzers_manager.AnalyzerReport", on_delete=models.CASCADE, related_name="data_model"
    )
    evaluation = models.CharField(
        max_length=100, null=True, blank=True, default=None
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
        models.CharField(max_length=100), default=list, blank=True
    )  # threats/related_threats, used as a pointer to other IOCs
    tags = pg_fields.ArrayField(
        models.CharField(max_length=100), null=True, blank=True, default=None
    )  # used for generic tags like phishing, malware, social_engineering
    # HybridAnalysisFileAnalyzer, MalwareBazaarFileAnalyzer, MwDB,
    # VirusTotalV3FileAnalyzer (report.data.attributes.tags)
    # GoogleSafeBrowsing, QuarkEngineAPK (crimes.crime)
    malware_family = models.CharField(
        max_length=100, null=True, blank=True, default=None
    )  # family/family_name/malware_family
    # HybridAnalysisObservable, Intezer (family_name), Cuckoo, MwDB,
    # Triage (analysis.family), UnpacMe (results.malware_id.malware_family),
    # VirusTotalV3FileAnalyzer
    # (attributes.last_analysis_results.list_el.results/attributes.names)
    additional_info = (
        models.JSONField(default=dict)
    )  # field for additional information related to a specific analyzer
    date = models.DateTimeField(default=now)
    TAGS = DataModelTags
    EVALUATIONS = DataModelEvaluations

    @classmethod
    def get_fields(cls) -> Dict:
        return {field.name: field for field in cls._meta.fields}

    @property
    def owner(self) -> User:
        return self.analyzer_report.user


class DomainDataModel(BaseDataModel):
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True, blank=True, default=None
    )  # pdns
    rank = models.IntegerField(null=True, blank=True, default=None)  # Tranco


class IPDataModel(BaseDataModel):
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True, blank=True, default=None
    )  # pdns
    asn = models.IntegerField(null=True, blank=True, default=None)  # BGPRanking, MaxMind
    asn_rank = models.DecimalField(null=True, blank=True, default=None, decimal_places=2, max_digits=3)  # BGPRanking
    certificates = models.JSONField(null=True, blank=True, default=None)  # CIRCL_PSSL
    org_name = models.CharField(max_length=100, null=True, blank=True, default=None)  # GreyNoise
    country = models.CharField(max_length=100, null=True, blank=True, default=None)  # MaxMind, AbuseIPDB
    country_code = models.CharField(max_length=100, null=True, blank=True, default=None)  # MaxMind, AbuseIPDB
    registered_country = models.CharField(
        max_length=100, null=True, blank=True, default=None
    )  # MaxMind, AbuseIPDB
    registered_country_code = models.CharField(
        max_length=100, null=True, blank=True, default=None
    )  # MaxMind, AbuseIPDB
    isp = models.CharField(max_length=100, null=True, blank=True, default=None)  # AbuseIPDB
    # additional_info
    # behavior = models.CharField(max_length=100, null=True)  # Crowdsec
    # noise = models.BooleanField(null=True)  # GreyNoise
    # riot = models.BooleanField(null=True)  # GreyNoise


class FileDataModel(BaseDataModel):
    signatures = models.ManyToManyField(Signature)  # ClamAvFileAnalyzer,
    # MalwareBazaarFileAnalyzer (signatures/yara_rules), Yara (report.list_el.match)
    # Yaraify (report.data.tasks.static_result)
    comments = pg_fields.ArrayField(
        models.CharField(max_length=100), default=list, blank=True
    )  # MalwareBazaarFileAnalyzer,
    # VirusTotalV3FileAnalyzer (data.relationships.comments)
    file_information = models.JSONField(
        default=dict,blank=True
    )  # MalwareBazaarFileAnalyzer, OneNoteInfo (files),
    # QuarkEngineAPK (crimes.confidence, threat_level, total_score)
    # RtfInfo (exploit_equation_editor, exploit_ole2link_vuln)
    stats = models.JSONField(default=dict, blank=True)  # PdfInfo (peepdf_stats)
    # additional_info
    # compromised_hosts = pg_fields.ArrayField(
    #   models.CharField(max_length=100), null=True
    # )  # HybridAnalysisFileAnalyzer
    # pdfid_reports = models.JSONField(null=True)  # PdfInfo
    # imphash = models.CharField(max_length=100, null=True)  # PeInfo
    # type = models.CharField(max_length=100, null=True)  # PeInfo
