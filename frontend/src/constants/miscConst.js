export const JobResultSections = Object.freeze({
  RAW: "raw",
  VISUALIZER: "visualizer",
});

export const TLPDescriptions = Object.freeze({
  CLEAR: "TLP: use all analyzers",
  GREEN: "TLP: disable analyzers that could impact privacy",
  AMBER:
    "TLP: disable analyzers that could impact privacy and limit access to my organization",
  RED: "TLP: disable analyzers that could impact privacy, limit access to my organization and do not use any external service",
});

export const HACKER_MEME_STRING =
  "LoOk At YoU hAcKeR a PaThEtIc CrEaTuRe Of MeAt AnD bOnE";

export const AuthScheme = Object.freeze({
  BASIC: "Basic",
  TOKEN: "Token",
  BEARER: "Bearer",
  X_API_KEY: "X-API-Key",
  API_KEY: "API-Key",
  X_AUTH_TOKEN: "X-Auth-Token",
  X_KEY: "X-Key",
  KEY: "key",
});
