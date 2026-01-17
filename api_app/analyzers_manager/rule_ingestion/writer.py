import os
import hashlib
import logging

logger = logging.getLogger(__name__)

YARA_RULES_DIR = "/opt/deploy/files_required/yara/unprotect_it"

def write_yara_rules(rules):
    os.makedirs(YARA_RULES_DIR, exist_ok = True)

    written = 0

    for rule in rules:
        if not isinstance(rule, str):
            continue


        rule_hash = hashlib.sha256(rule.encode()).hexdigest()
        file_path = os.path.join(YARA_RULES_DIR, f"{rule_hash}.yar")

        if os.path.exists(file_path):
            continue

        with open(file_path, "w")  as f:
            f.write(rule)

        written +=1
        logger.info(f"Written YARA rule hash={rule_hash}")
        logger.debug(rule[:200])

    logger.info(f"Wrote {written} YARA rules to disk")
    return written
