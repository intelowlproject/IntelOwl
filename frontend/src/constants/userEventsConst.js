import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_IP_WILDCARD,
  USER_EVENT_DOMAIN_WILDCARD,
} from "./apiURLs";
import { DataModelEvaluations } from "./dataModelConst";

export const DecayProgressionTypes = Object.freeze({
  LINEAR: "0",
  INVERSE_EXPONENTIAL: "1",
  FIXED: "2",
});

export const DecayProgressionDescription = Object.freeze({
  0: "Reliability decreases by 1 point every N days, N is defined by the 'Decay days' field.",
  1: "Reliability decreases by 1 point in an inversely exponential manner (e.g. rel=10, after N days: rel=9, after N*N days: rel=8). N is defined by the 'Decay days' field.",
  2: "Reliability remains fixed over time, so the evaluation does not decay.",
});

export const UserEventTypes = Object.freeze({
  ANALYZABLE: "artifact",
  IP_WILDCARD: "ip_wildcard",
  DOMAIN_WILDCARD: "domain_wildcard",
});

export const userEventTypesToApiMapping = Object.freeze({
  artifact: USER_EVENT_ANALYZABLE,
  ip_wildcard: USER_EVENT_IP_WILDCARD,
  domain_wildcard: USER_EVENT_DOMAIN_WILDCARD,
});

export const basicEvaluationReliabilityOption = Object.freeze({
  RELIABILITY_CONFIRMED_MALICIOUS: 10,
  RELIABILITY_MALICIOUS: 7,
  RELIABILITY_CURRENTLY_TRUSTED: 8,
  RELIABILITY_TRUSTED: 10,
});

export const basicEvaluationOptions = Object.freeze({
  CONFIRMED_MALICIOUS: "0",
  MALICIOUS: "1",
  CURRENTLY_TRUSTED: "2",
  TRUSTED: "3",
});

export const evaluationOptions = Object.freeze({
  0: {
    evaluation: DataModelEvaluations.MALICIOUS,
    label: "Confirmed malicious",
    reliability:
      basicEvaluationReliabilityOption.RELIABILITY_CONFIRMED_MALICIOUS,
    description:
      "Artifact that has been verified as actively involved in malicious activity (phishing site, download sample, c2, ...).",
  },
  1: {
    evaluation: DataModelEvaluations.MALICIOUS,
    label: "Malicious",
    reliability: basicEvaluationReliabilityOption.RELIABILITY_MALICIOUS,
    description:
      "Artifact that is associated with potentially malicious operations (connectivity check, etc.).",
  },
  2: {
    evaluation: DataModelEvaluations.TRUSTED,
    label: "Currently trusted",
    reliability: basicEvaluationReliabilityOption.RELIABILITY_CURRENTLY_TRUSTED,
    description:
      "Artifact that shows no sign of malicious behavior at present, though its status could change over time.",
  },
  3: {
    evaluation: DataModelEvaluations.TRUSTED,
    label: "Trusted",
    reliability: basicEvaluationReliabilityOption.RELIABILITY_TRUSTED,
    description:
      "A well-known and trusted artifact associated with a widely used legitimate service (es: google.com, 8.8.8.8, etc...)",
  },
});
