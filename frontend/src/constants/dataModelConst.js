/* eslint-disable id-length */
export const DataModelEvaluationIcons = Object.freeze({
  trusted: "like",
  malicious: "malware",
});

export const DataModelTags = Object.freeze({
  PHISHING: "phishing",
  MALWARE: "malware",
  SOCIAL_ENGINEERING: "social_engineering",
  ANONYMIZER: "anonymizer",
  TOR_EXIT_NODE: "tor_exit_node",
  ABUSED: "abused",
});

export const DataModelTagsIcons = Object.freeze({
  phishing: "hook",
  anonymizer: "incognito",
  malware: "malware",
  social_engineering: "creditCard",
  tor_exit_node: "tor",
  scanner: "magnifyingGlass",
  ip_only: "networkNode",
});

export const DataModelEvaluations = Object.freeze({
  TRUSTED: "trusted",
  MALICIOUS: "malicious",
});

export const DataModelKillChainPhases = Object.freeze({
  RECONNAISSANCE: "reconnaissance",
  WEAPONIZATION: "weaponization",
  DELIVERY: "delivery",
  EXPLOITATION: "exploitation",
  INSTALLATION: "installation",
  C2: "c2",
  ACTION: "action",
});

export const DataModelKillChainPhasesDescriptions = Object.freeze({
  RECONNAISSANCE:
    "Attackers research their target to identify vulnerabilities, gathering information on security defenses, corporate structure, and potential entry points.",
  WEAPONIZATION:
    "The attacker crafts a malicious payload, such as a virus or malware, tailored to exploit the identified weaknesses.",
  DELIVERY:
    "The weaponized payload is sent to the target, often through methods like phishing emails or malicious links.",
  EXPLOITATION:
    "The malicious code runs on the target system, exploiting the vulnerability and gaining access.",
  INSTALLATION:
    "The malware establishes persistent access on the compromised system, often by installing backdoors or trojans.",
  C2: "Attackers establish a remote communication channel with the compromised system to issue commands and control their operation.",
  ACTION:
    "The final phase where attackers achieve their ultimate goals, such as stealing data exfiltrating them, encrypting files for ransom, or disrupting services.",
});
