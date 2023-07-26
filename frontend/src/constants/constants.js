export const pluginType = Object.freeze({
  ANALYZER: "1",
  CONNECTOR: "2",
  VISUALIZER: "3",
});

export const configType = Object.freeze({
  PARAMETER: "1",
  SECRET: "2",
});

export const scanMode = Object.freeze({
  FORCE_NEW_ANALYSIS: "1",
  CHECK_PREVIOUS_ANALYSIS: "2",
});
