// api/ auth
export const API_BASE_URI = "/api";

// intelowl core
export const JOB_BASE_URI = `${API_BASE_URI}/jobs`;
export const COMMENT_BASE_URI = `${API_BASE_URI}/comments`;
export const TAG_BASE_URI = `${API_BASE_URI}/tags`;
export const ASK_MULTI_ANALYSIS_AVAILABILITY_URI = `${API_BASE_URI}/ask_multi_analysis_availability`;
export const ANALYZE_MULTIPLE_FILES_URI = `${API_BASE_URI}/analyze_multiple_files`;
export const ANALYZE_MULTIPLE_OBSERVABLE_URI = `${API_BASE_URI}/analyze_multiple_observables`;
export const ANALYZERS_CONFIG_URI = `${API_BASE_URI}/analyzer`;
export const CONNECTORS_CONFIG_URI = `${API_BASE_URI}/connector`;
export const VISUALIZERS_CONFIG_URI = `${API_BASE_URI}/visualizer`;
export const PLAYBOOKS_CONFIG_URI = `${API_BASE_URI}/playbook`;

export const JOB_AGG_STATUS_URI = `${JOB_BASE_URI}/aggregate/status`;
export const JOB_AGG_TYPE_URI = `${JOB_BASE_URI}/aggregate/type`;
export const JOB_AGG_OBS_CLASSIFICATION_URI = `${JOB_BASE_URI}/aggregate/observable_classification`;
export const JOB_AGG_FILE_MIMETYPE_URI = `${JOB_BASE_URI}/aggregate/file_mimetype`;
export const JOB_AGG_OBS_NAME_URI = `${JOB_BASE_URI}/aggregate/observable_name`;
export const JOB_AGG_FILE_MD5_URI = `${JOB_BASE_URI}/aggregate/md5`;

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
export const SESSIONS_BASE_URI = `${AUTH_BASE_URI}/sessions`;
export const APIACCESS_BASE_URI = `${AUTH_BASE_URI}/apiaccess`;
