export const JOB_TYPE = Object.freeze({
  FILE: "file",
  OBSERVABLE: "observable",
});
export const FILE_MIME_TYPES = Object.freeze({
  // IMPORTANT! in case you update this Object remember to update also the blackend
  WSCRIPT: "application/w-script-file",
  JAVASCRIPT1: "application/javascript",
  JAVASCRIPT2: "application/x-javascript",
  JAVASCRIPT3: "text/javascript",
  VB_SCRIPT: "application/x-vbscript",
  IQY: "text/x-ms-iqy",
  APK: "application/vnd.android.package-archive",
  DEX: "application/x-dex",
  ONE_NOTE: "application/onenote",
  ZIP1: "application/zip",
  ZIP2: "multipart/x-zip",
  JAVA: "application/java-archive",
  RTF1: "text/rtf",
  RTF2: "application/rtf",
  DOS: "application/x-dosexec",
  SHARED_LIB: "application/x-sharedlib",
  EXE: "application/x-executable",
  ELF: "application/x-elf",
  OCTET: "application/octet-stream",
  PCAP: "application/vnd.tcpdump.pcap",
  PDF: "application/pdf",
  HTML: "text/html",
  PUB: "application/x-mspublisher",
  EXCEL_MACRO1: "application/vnd.ms-excel.addin.macroEnabled",
  EXCEL_MACRO2: "application/vnd.ms-excel.sheet.macroEnabled.12",
  EXCEL1: "application/vnd.ms-excel",
  EXCEL2: "application/excel",
  DOC: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  XML1: "application/xml",
  XML2: "text/xml",
  ENCRYPTED: "application/encrypted",
  PLAIN: "text/plain",
  CSV: "text/csv",
  PPTX: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  WORD1: "application/msword",
  WORD2:
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  POWERPOINT: "application/vnd.ms-powerpoint",
  OFFICE: "application/vnd.ms-office",
  BINARY: "application/x-binary",
  MAC1: "application/x-macbinary",
  MAC2: "application/mac-binary",
  MAC3: "application/x-mach-binary",
  COMPRESS1: "application/x-zip-compressed",
  COMPRESS2: "application/x-compressed",
  OUTLOOK: "application/vnd.ms-outlook",
  EML: "message/rfc822",
  PKCS7: "application/pkcs7-signature",
  XPKCS7: "application/x-pkcs7-signature",
  MIXED: "multipart/mixed",
  X_SHELLSCRIPT: "text/x-shellscript",
});
export const OBSERVABLE_CLASSIFICATION = Object.freeze({
  IP: "ip",
  URL: "url",
  DOMAIN: "domain",
  HASH: "hash",
  GENERIC: "generic",
});
// colors
export const JOB_TYPE_COLOR_MAP = Object.freeze({
  file: "#ed896f",
  observable: "#42796f",
});
export const TLP_COLOR_MAP = Object.freeze({
  CLEAR: "#FFFFFF",
  GREEN: "#33FF00",
  AMBER: "#FFC000",
  RED: "#FF0033",
});

export const OBSERVABLE_CLASSIFICATION_COLOR_MAP = Object.freeze({
  ip: "#9aa66c",
  url: "#7da7d3",
  domain: "#8070ed",
  hash: "#ed896f",
  generic: "#733010",
});
export const TLP_DESCRIPTION_MAP = Object.freeze({
  CLEAR: "TLP: use all analyzers",
  GREEN: "TLP: disable analyzers that could impact privacy",
  AMBER:
    "TLP: disable analyzers that could impact privacy and limit access to my organization",
  RED: "TLP: disable analyzers that could impact privacy, limit access to my organization and do not use any external service",
});
export const JOB_STATUS_COLOR_MAP = Object.freeze({
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
export const REPORT_STATUS_COLOR_MAP = Object.freeze({
  pending: "light",
  running: "secondary",
  killed: "gray",
  success: "success",
  failed: "danger",
});
export const STATUS_COLORMAP = Object.freeze({
  ...JOB_STATUS_COLOR_MAP,
  ...REPORT_STATUS_COLOR_MAP,
});
export const TLP_CHOICES = Object.keys(TLP_COLOR_MAP);

export const scanTypes = Object.freeze({
  playbooks: "Playbooks",
  analyzers_and_connectors: "Analyzers/Connectors",
});

export const HACKER_MEME_STRING =
  "LoOk At YoU hAcKeR a PaThEtIc CrEaTuRe Of MeAt AnD bOnE";
export const EMAIL_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i;
export const URL_REGEX = "(www.|http://|https://).*";
export const UUID_REGEX =
  /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i;
export const PASSWORD_REGEX = /^(?=.*[a-zA-Z])[a-zA-Z0-9]{12,}$/i;
