// HTTP(S)
// api/ auth
export const API_BASE_URI = "/api";

// intelowl core
export const JOB_BASE_URI = `${API_BASE_URI}/jobs`;
export const INVESTIGATION_BASE_URI = `${API_BASE_URI}/investigation`;
export const COMMENT_BASE_URI = `${API_BASE_URI}/comments`;
export const TAG_BASE_URI = `${API_BASE_URI}/tags`;
export const ASK_MULTI_ANALYSIS_AVAILABILITY_URI = `${API_BASE_URI}/ask_multi_analysis_availability`;
export const ANALYZE_MULTIPLE_FILES_URI = `${API_BASE_URI}/analyze_multiple_files`;
export const ANALYZE_MULTIPLE_OBSERVABLE_URI = `${API_BASE_URI}/analyze_multiple_observables`;
export const ANALYZERS_CONFIG_URI = `${API_BASE_URI}/analyzer`;
export const CONNECTORS_CONFIG_URI = `${API_BASE_URI}/connector`;
export const PIVOTS_CONFIG_URI = `${API_BASE_URI}/pivot`;
export const VISUALIZERS_CONFIG_URI = `${API_BASE_URI}/visualizer`;
export const INGESTORS_CONFIG_URI = `${API_BASE_URI}/ingestor`;
export const PLAYBOOKS_CONFIG_URI = `${API_BASE_URI}/playbook`;
export const PLAYBOOKS_ANALYZE_MULTIPLE_FILES_URI = `${PLAYBOOKS_CONFIG_URI}/analyze_multiple_files`;
export const PLAYBOOKS_ANALYZE_MULTIPLE_OBSERVABLE_URI = `${PLAYBOOKS_CONFIG_URI}/analyze_multiple_observables`;
export const ANALYZABLES_URI = `${API_BASE_URI}/analyzable`;

const AGGREGATE_PATH = "/aggregate";
export const JOB_AGG_STATUS_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/status`;
export const JOB_AGG_TYPE_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/type`;
export const JOB_AGG_OBS_CLASSIFICATION_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/observable_classification`;
export const JOB_AGG_FILE_MIMETYPE_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/file_mimetype`;
export const JOB_AGG_TOP_PLAYBOOK_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/top_playbook`;
export const JOB_AGG_TOP_USER_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/top_user`;
export const JOB_AGG_TOP_TLP_URI = `${JOB_BASE_URI}${AGGREGATE_PATH}/top_tlp`;

export const JOB_RECENT_SCANS = `${JOB_BASE_URI}/recent_scans`;
export const JOB_RECENT_SCANS_USER = `${JOB_BASE_URI}/recent_scans_user`;

export const PLUGIN_REPORT_QUERIES = `${API_BASE_URI}/plugin_report_queries`;

// user
export const USERACCESS_URI = `${API_BASE_URI}/me/access`;
export const PLUGIN_CONFIG_URI = `${API_BASE_URI}/plugin-config`;

// org
export const BASE_URI_ORG = `${API_BASE_URI}/me/organization`;
export const BASE_URI_INVITATION = `${API_BASE_URI}/me/invitations`;

export const ORG_PLUGIN_DISABLE_URI = `${API_BASE_URI}/plugin-disable`;

// notifications
export const NOTIFICATION_BASE_URI = `${API_BASE_URI}/notification`;

// auth
export const AUTH_BASE_URI = `${API_BASE_URI}/auth`;
export const APIACCESS_BASE_URI = `${AUTH_BASE_URI}/apiaccess`;

// WEBSOCKETS
const WEBSOCKET_BASE_URI = "ws";
export const WEBSOCKET_JOBS_URI = `${WEBSOCKET_BASE_URI}/jobs`;

// user event
export const USER_EVENT_BASE_URI = `${API_BASE_URI}/user_event`;
export const USER_EVENT_ANALYZABLE = `${USER_EVENT_BASE_URI}/analyzable`;
export const USER_EVENT_IP_WILDCARD = `${USER_EVENT_BASE_URI}/ip_wildcard`;
export const USER_EVENT_DOMAIN_WILDCARD = `${USER_EVENT_BASE_URI}/domain_wildcard`;
