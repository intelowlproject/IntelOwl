// colors
export const JOB_TYPE_COLOR_MAP = Object.freeze({
  file: "#ed896f",
  observable: "#42796f",
});
export const TLP_COLOR_MAP = Object.freeze({
  CLEAR: "#FFFFFF",
  GREEN: "#33FF00",
  AMBER: "#FFC000",
  RED: "#FF0033",
});

export const OBSERVABLE_CLASSIFICATION_COLOR_MAP = Object.freeze({
  ip: "#9aa66c",
  url: "#7da7d3",
  domain: "#8070ed",
  hash: "#ed896f",
  generic: "#733010",
});
export const TLP_DESCRIPTION_MAP = Object.freeze({
  CLEAR: "TLP: use all analyzers",
  GREEN: "TLP: disable analyzers that could impact privacy",
  AMBER:
    "TLP: disable analyzers that could impact privacy and limit access to my organization",
  RED: "TLP: disable analyzers that could impact privacy, limit access to my organization and do not use any external service",
});

export const JOB_STATUS_COLOR_MAP = Object.freeze({
  pending: "light",
  running: "secondary",
  analyzers_running: "secondary",
  connectors_running: "secondary",
  pivots_running: "secondary",
  visualizers_running: "secondary",

  analyzers_completed: "secondary",
  connectors_completed: "secondary",
  pivots_completed: "secondary",
  visualizers_completed: "secondary",

  killed: "gray",
  reported_with_fails: "warning",
  reported_without_fails: "success",
  failed: "danger",
});
export const REPORT_STATUS_COLOR_MAP = Object.freeze({
  pending: "light",
  running: "secondary",
  killed: "gray",
  success: "success",
  failed: "danger",
});
export const STATUS_COLORMAP = Object.freeze({
  ...JOB_STATUS_COLOR_MAP,
  ...REPORT_STATUS_COLOR_MAP,
});