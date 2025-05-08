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

export const HTTPMethods = Object.freeze({
  GET: "get",
  POST: "post",
  PUT: "put",
  PATCH: "patch",
  DELETE: "delete",
});

export const datetimeFormatStr = "yyyy-MM-dd'T'HH:mm:ss";

export const HistoryPages = Object.freeze({
  JOBS: "jobs",
  INVESTIGAITONS: "investigations",
  USER_REPORTS: "user-reports",
});
