import {
  USER_EVENT_ANALYZABLE,
  USER_EVENT_IP_WILDCARD,
  USER_EVENT_DOMAIN_WILDCARD,
} from "./apiURLs";

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

export const TrustedReliabilityDescription = Object.freeze({
  0: "Trusted test",
  1: "Trusted test",
  2: "Trusted test",
  3: "Trusted test",
  4: "Trusted test",
  5: "Trusted test",
  6: "Trusted test",
  7: "Trusted test",
  8: "Trusted test",
  9: "Trusted test",
  10: "Trusted test",
});

export const MaliciousReliabilityDescription = Object.freeze({
  0: "test",
  1: "test",
  2: "test",
  3: "test",
  4: "test",
  5: "test",
  6: "test",
  7: "test",
  8: "test",
  9: "test",
  10: "Reliability decreases by 1 point in an inversely exponential (e.g. rel=10, after N days: rel=9, after N*N days: rel=8). N is defined by the 'Decay days' field.",
});
