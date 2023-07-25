export const pluginType = Object.freeze({
  ANALYZER: "1",
  CONNECTOR: "2",
  VISUALIZER: "3",
});

export const pluginStatuses = Object.freeze({
  PENDING: "PENDING",
  RUNNING: "RUNNING",
  KILLED: "KILLED",
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
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
