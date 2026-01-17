import logging
logger = logging.getLogger(__name__)

def classify_rules(rules):
    """
   Classify unprotect.it rules by engine.
   Returns a dict with keys: 'yara', 'capa'

    """
    classified = {
        "yara":[],
        "capa":[],
    }

    for rule in rules:
        if not isinstance(rule,dict):
            continue


        rule_type = rule.get("type", {}).get("name")
        rule_content = rule.get("rule")

        if not rule_type or not rule_content:
            continue

        if rule_type.lower() == "yara":
            classified["yara"].append(rule_content)

        elif rule_type.lower() == "capa":
            classified["capa"].append(rule_content)



    return classified