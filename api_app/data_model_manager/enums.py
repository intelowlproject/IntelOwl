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
    SCANNER = "scanner"
    # IMPORTANT! update DataModelTags Object in frontend!


class DataModelEvaluations(Choices):
    TRUSTED = "trusted"
    MALICIOUS = "malicious"


class DataModelVerdictBuckets(Choices):
    """Presentation buckets shared by the DataModel visualizer and the chatbot.

    Only two of the five are evaluations: TRUSTED and MALICIOUS take their values from
    DataModelEvaluations so the two vocabularies cannot drift apart. The other three have no
    evaluation counterpart and are deliberately not added to DataModelEvaluations — CLEAN and
    SUSPICIOUS mean "that evaluation, but below its reliability floor", and NO_EVALUATION means
    no analyzer expressed an opinion at all. They describe how a verdict is *shown*, not what an
    analyzer *concluded*.
    """

    TRUSTED = DataModelEvaluations.TRUSTED.value
    CLEAN = "clean"
    MALICIOUS = DataModelEvaluations.MALICIOUS.value
    SUSPICIOUS = "suspicious"
    NO_EVALUATION = "no evaluation"


class DataModelKillChainPhases(Choices):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "c2"
    ACTION = "action"
