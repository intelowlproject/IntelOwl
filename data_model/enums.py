from django.db.models import Choices


class SignaturesChoices(Choices):
    CLAMAV = "Clamav"
    SIGMA = "Sigma"
    YARA = "Yara"
    SURICATA = "Suricata"


class DataModelTags(Choices):
    PHISHING = "Phishing"
    MALWARE = "Malware"
    SOCIAL_ENGINEERING = "SocialEngineering"
    ANONYMIZER = "Anonymizer"
    TOR_EXIT_NODE = "TorExitNode"
