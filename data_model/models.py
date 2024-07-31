from django.contrib.postgres import fields as pg_fields
from django.db import models


class IETFReport(models.Model):
    rrname = models.CharField()
    rrtype = models.CharField()
    rdata = pg_fields.ArrayField(models.CharField())
    time_first = models.DateTimeField()
    time_last = models.DateTimeField()


class DomainDataModel(models.Model):
    evaluation = models.CharField(null=True)
    classification = models.CharField(
        null=True
    )  # HybridAnalysisObservable (verdict), BasicMaliciousDetector
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    tranco_rank = models.IntegerField(null=True)  # Tranco
    related_url = models.URLField(
        null=True
    )  # Crowdsec (link), UrlHaus (external_references)


class IPDataModel(models.Model):
    evaluation = models.CharField(null=True)
    classification = models.CharField(
        null=True
    )  # Crowdsec, GreyNoise, HybridAnalysisObservable (verdict), BasicMaliciousDetector
    ietf_report = models.ForeignKey(
        IETFReport, on_delete=models.CASCADE, null=True
    )  # pdns
    asn = models.IntegerField(null=True)  # BGPRanking
    asn_rank = models.DecimalField(null=True)  # BGPRanking
    circl_pssl_certificates = models.JSONField(null=True)  # CIRCL_PSSL
    behavior = models.CharField(null=True)  # Crowdsec
    related_url = models.URLField(
        null=True
    )  # Crowdsec (link), UrlHaus (external_references)
    noise = models.BooleanField(null=True)  # GreyNoise
    riot = models.BooleanField(null=True)  # GreyNoise
    org_name = models.CharField(null=True)  # GreyNoise
    vx_family = models.CharField(null=True)  # HybridAnalysisObservable


class HashDataModel(models.Model):
    classification_tags = pg_fields.ArrayField(
        models.CharField(), null=True
    )  # HybridAnalysisFileAnalyzer
    tags = pg_fields.ArrayField(
        models.CharField(), null=True
    )  # HybridAnalysisFileAnalyzer
    domains = pg_fields.ArrayField(
        models.CharField(), null=True
    )  # HybridAnalysisFileAnalyzer
    compromised_hosts = pg_fields.ArrayField(
        models.CharField(), null=True
    )  # HybridAnalysisFileAnalyzer
