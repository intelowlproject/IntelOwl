export const PluginTypes = Object.freeze({
  ANALYZER: "1",
  CONNECTOR: "2",
  VISUALIZER: "3",
  INGESTOR: "4",
  PIVOT: "5",
});

export const PluginStatuses = Object.freeze({
  PENDING: "PENDING",
  RUNNING: "RUNNING",
  KILLED: "KILLED",
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
});

export const PluginFinalStatuses = Object.freeze({
  KILLED: "KILLED",
  SUCCESS: "SUCCESS",
  FAILED: "FAILED",
});

export const PluginConfigTypes = Object.freeze({
  PARAMETER: "1",
  SECRET: "2",
});
