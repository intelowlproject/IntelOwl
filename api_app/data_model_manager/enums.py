from django.db.models import Choices


class SignatureProviderChoices(Choices):
    CLAMAV = "ClamAV"
    SIGMA = "Sigma"
    YARA = "Yara"
    SURICATA = "Suricata"


class DataModelTags(Choices):
    PHISHING = "Phishing"
    MALWARE = "Malware"
    SOCIAL_ENGINEERING = "SocialEngineering"
    ANONYMIZER = "Anonymizer"
    TOR_EXIT_NODE = "TorExitNode"


class DataModelEvaluations(Choices):
    FALSE_POSITIVE = "FalsePositive"
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
