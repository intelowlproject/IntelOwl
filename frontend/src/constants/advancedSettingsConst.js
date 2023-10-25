export const ScanTypes = Object.freeze({
  playbooks: "Playbooks",
  analyzers_and_connectors: "Analyzers/Connectors",
});

export const ScanModesNumeric = Object.freeze({
  FORCE_NEW_ANALYSIS: "1",
  CHECK_PREVIOUS_ANALYSIS: "2",
});

export const TLPs = Object.freeze({
  CLEAR: "CLEAR",
  GREEN: "GREEN",
  AMBER: "AMBER",
  RED: "RED",
});

export const TlpChoices = Object.values(TLPs);
