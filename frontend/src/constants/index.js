// app specific
export const JOB_TYPE_COLOR_MAP = {
  file: "#ed896f",
  observable: "#42796f",
};
export const TLP_COLOR_MAP = {
  CLEAR: "#FFFFFF",
  GREEN: "#33FF00",
  AMBER: "#FFC000",
  RED: "#FF0033",
};
export const OBSERVABLE_CLASSIFICATION_COLOR_MAP = {
  ip: "#9aa66c",
  url: "#7da7d3",
  domain: "#8070ed",
  hash: "#ed896f",
  generic: "#733010",
};
export const TLP_DESCRIPTION_MAP = {
  CLEAR: "TLP: use all analyzers",
  GREEN: "TLP: disable analyzers that could impact privacy",
  AMBER:
    "TLP: disable analyzers that could impact privacy and limit access to my organization",
  RED: "TLP: disable analyzers that could impact privacy, limit access to my organization and do not use any external service",
};
export const JOB_STATUS_COLOR_MAP = {
  pending: "light",
  running: "secondary",
  killed: "gray",
  reported_with_fails: "warning",
  reported_without_fails: "success",
  failed: "danger",
};
export const REPORT_STATUS_COLOR_MAP = {
  pending: "light",
  running: "secondary",
  killed: "gray",
  success: "success",
  failed: "danger",
};
export const STATUS_COLORMAP = {
  ...JOB_STATUS_COLOR_MAP,
  ...REPORT_STATUS_COLOR_MAP,
};
export const JOB_STATUSES = [
  "pending",
  "running",
  "reported_with_fails",
  "reported_without_fails",
  "killed",
  "failed",
];
export const PLUGIN_STATUSES = [
  "PENDING",
  "RUNNING",
  "KILLED",
  "SUCCESS",
  "FAILED",
];
export const TLP_CHOICES = Object.keys(TLP_COLOR_MAP);
export const OBSERVABLE_TYPES = Object.keys(
  OBSERVABLE_CLASSIFICATION_COLOR_MAP
);

export const scanTypes = {
  playbooks: "Playbooks",
  analyzers_and_connectors: "Analyzers/Connectors",
};

export const ALL_CLASSIFICATIONS = OBSERVABLE_TYPES.concat("file");

export const HACKER_MEME_STRING =
  "LoOk At YoU hAcKeR a PaThEtIc CrEaTuRe Of MeAt AnD bOnE";
export const EMAIL_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i;
export const URL_REGEX = "(www.|http://|https://).*";
export const UUID_REGEX =
  /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i;
export const PASSWORD_REGEX = /^(?=.*[a-zA-Z])[a-zA-Z0-9]{12,}$/i;
