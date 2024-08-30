from django.db.models import Choices


class SignaturesChoices(Choices):
    CLAMAV = "Clamav"
    SIGMA = "Sigma"
    YARA = "Yara"
    SURICATA = "Suricata"
