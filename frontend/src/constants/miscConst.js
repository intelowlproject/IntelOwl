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
export const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

export const HistoryPages = Object.freeze({
  JOBS: "jobs",
  INVESTIGAITONS: "investigations",
  USER_EVENTS: "user-events",
  USER_DOMAIN_WILDCARD_EVENTS: "user-domain-wildcard-events",
  USER_IP_WILDCARD_EVENTS: "user-ip-wildcard-events",
});

export const Classifications = Object.freeze({
  IP: "ip",
  URL: "url",
  DOMAIN: "domain",
  HASH: "hash",
  GENERIC: "generic",
  FILE: "file",
});

export const AnalyzableHistoryTypes = Object.freeze({
  JOB: "job",
  USER_EVENT: "user_evaluation",
  USER_DOMAIN_WILDCARD_EVENT: "user_domain_wildcard_evaluation",
  USER_IP_WILDCARD_EVENT: "user_ip_wildcard_evaluation",
});
