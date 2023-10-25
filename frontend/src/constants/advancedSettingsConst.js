export const scanTypes = Object.freeze({
  playbooks: "Playbooks",
  analyzers_and_connectors: "Analyzers/Connectors",
});

export const scanMode = Object.freeze({
  FORCE_NEW_ANALYSIS: "1",
  CHECK_PREVIOUS_ANALYSIS: "2",
});

export const Tlp = Object.freeze({
  CLEAR: "clear",
  GREEN: "green",
  AMBER: "amber",
  RED: "red",
});

export const TLP_CHOICES = Object.keys(Tlp);
