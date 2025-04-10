export const JobTypeColors = Object.freeze({
  file: "#ed896f",
  observable: "#42796f",
});

export const TLPColors = Object.freeze({
  CLEAR: "#FFFFFF",
  GREEN: "#33FF00",
  AMBER: "#FFC000",
  RED: "#FF0033",
});

export const ObservableClassificationColors = Object.freeze({
  ip: "#9aa66c",
  url: "#7da7d3",
  domain: "#8070ed",
  hash: "#ed896f",
  generic: "#733010",
});

export const JobStatusColors = Object.freeze({
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

export const ReportStatusColors = Object.freeze({
  pending: "light",
  running: "secondary",
  killed: "gray",
  success: "success",
  failed: "danger",
});

export const InvestigationStatusColors = Object.freeze({
  created: "light",
  running: "secondary",
  concluded: "success",
});

export const StatusColors = Object.freeze({
  ...JobStatusColors,
  ...ReportStatusColors,
  ...InvestigationStatusColors,
});

export const EvaluationColors = Object.freeze({
  trusted: "success",
  malicious: "danger",
});

export const TagsColors = Object.freeze({
  phishing: "danger",
  anonymizer: "warning",
  malware: "danger",
  social_engineering: "secondary",
  tor_exit_node: "warning",
  scanner: "danger",
  ip_only: "secondary",
});
