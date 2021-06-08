from django.db import models
from django.contrib.postgres import fields as postgres_fields
from cache_memoize import cache_memoize

from intel_owl.secrets import get_secret
from api_app.models import Job


class Analyzer(models.Model):
    CHOICES = (
        ("file_analyzer", "file_analyzer"),
        ("observable_analyzer", "observable_analyzer"),
    )
    analyzer_type = models.CharField(
        max_length=50,
        choices=CHOICES,
    )
    disabled = models.BooleanField(default=False, blank=False)
    description = models.TextField()
    python_module = models.CharField(max_length=128, blank=False, null=False)
    config = postgres_fields.JSONField(default=dict, blank=False, null=False)

    @property
    def _cached_secrets(self) -> dict:
        return self.__cached_secrets

    @cache_memoize(100, args_rewrite=lambda o: o.pk)
    def verify_secrets(self) -> dict:
        verification = {
            "configured:": False,
            "error_message": None,
            "missing_secrets": [],
        }
        for secret in self.secrets.all():
            var = get_secret(secret.env_variable_key)
            if var:
                self.__cached_secrets[secret.name] = var
            else:
                verification["missing_secrets"].append(secret.name)

        if len(verification["missing_secrets"]) == 0:
            verification["configured"] = True
        else:
            total_secrets = self.secrets.all().count()
            verified_secrets = total_secrets - len(verification["missing_secrets"])
            verification[
                "error_message"
            ] = f'{verification["missing_secrets"]} missing ({verified_secrets} of {total_secrets} satisfied)'  # noqa: E501

        return verification


class AnalyzerReport(models.Model):
    analyzer = models.ForeignKey(
        Analyzer, related_name="reports", on_delete=models.CASCADE
    )
    job = models.ForeignKey(
        Job, related_name="analyzer_reports", on_delete=models.CASCADE
    )

    success = models.BooleanField(default=False)
    report = postgres_fields.JSONField(default=dict, blank=False, null=False)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512, blank=True, default=list)
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()


class Secret(models.Model):
    CHOICES = (("str", "str"), ("int", "int"), ("bool", "bool"), ("float", "float"))

    name = models.CharField(max_length=50, blank=False, null=False, unique=True)
    env_variable_key = models.CharField(max_length=50)
    datatype = models.CharField(
        max_length=8,
        choices=CHOICES,
    )
    required = models.BooleanField(blank=False, default=True)
    default = models.CharField(max_length=50, null=True)
    description = models.TextField()

    analyzer = models.ForeignKey(
        Analyzer, related_name="secrets", on_delete=models.CASCADE
    )
