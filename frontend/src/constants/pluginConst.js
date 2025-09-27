export const PluginTypesNumeric = Object.freeze({
  ANALYZER: "1",
  CONNECTOR: "2",
  VISUALIZER: "3",
  INGESTOR: "4",
  PIVOT: "5",
});

export const PluginsTypes = Object.freeze({
  ANALYZER: "analyzer",
  CONNECTOR: "connector",
  VISUALIZER: "visualizer",
  INGESTOR: "ingestor",
  PIVOT: "pivot",
  PLAYBOOK: "playbook",
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

export const PluginConfigTypesNumeric = Object.freeze({
  PARAMETER: "1",
  SECRET: "2",
});

export const PluginConfigTypes = Object.freeze({
  USER_CONFIG: "userConfig",
  ORG_CONFIG: "orgConfig",
});

export const ParameterTypes = Object.freeze({
  INT: "int",
  FLOAT: "float",
  STR: "str",
  BOOL: "bool",
  LIST: "list",
  DICT: "dict",
});
