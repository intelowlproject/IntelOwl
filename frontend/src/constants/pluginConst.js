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

export const pluginConfigType = Object.freeze({
  PARAMETER: "1",
  SECRET: "2",
});
