export const pluginType = Object.freeze({
  ANALYZER: "1",
  CONNECTOR: "2",
  VISUALIZER: "3",
  INGESTOR: "4",
  PIVOT: "5",
});

export const pluginStatuses = Object.freeze({
  PENDING: "PENDING",
  RUNNING: "RUNNING",
  KILLED: "KILLED",
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
});

export const pluginFinalStatuses = Object.freeze({
  KILLED: "KILLED",
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
});

// IMPORTANT - do not change the order of status
export const jobStatuses = Object.freeze({
  PENDING: "pending",
  RUNNING: "running",
  ANALYZERS_RUNNING: "analyzers_running",
  ANALYZERS_COMPLETED: "analyzers_completed",
  CONNECTORS_RUNNING: "connectors_running",
  CONNECTORS_COMPLETED: "connectors_completed",
  PIVOTS_RUNNING: "pivots_running",
  PIVOTS_COMPLETED: "pivots_completed",
  VISUALIZERS_RUNNING: "visualizers_running",
  VISUALIZERS_COMPLETED: "visualizers_completed",
  REPORTED_WITH_FAILS: "reported_with_fails",
  REPORTED_WITHOUT_FAILS: "reported_without_fails",
  KILLED: "killed",
  FAILED: "failed",
});

export const jobFinalStatuses = Object.freeze({
  REPORTED_WITHOUT_FAILS: "reported_without_fails",
  REPORTED_WITH_FAILS: "reported_with_fails",
  KILLED: "killed",
  FAILED: "failed",
});

export const configType = Object.freeze({
  PARAMETER: "1",
  SECRET: "2",
});

export const scanMode = Object.freeze({
  FORCE_NEW_ANALYSIS: "1",
  CHECK_PREVIOUS_ANALYSIS: "2",
});
