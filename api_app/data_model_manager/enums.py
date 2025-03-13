from django.db.models import Choices


class SignatureProviderChoices(Choices):
    CLAMAV = "clam_av"
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"


class DataModelTags(Choices):
    PHISHING = "phishing"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    ANONYMIZER = "anonymizer"
    TOR_EXIT_NODE = "tor_exit_node"
    ABUSED = "abused"


class DataModelEvaluations(Choices):
    TRUSTED = "trusted"
    MALICIOUS = "malicious"
