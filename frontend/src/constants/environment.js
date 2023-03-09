/* eslint-disable prefer-destructuring */
export const INTELOWL_DOCS_URL = "https://intelowl.readthedocs.io/en/latest/";
export const PYINTELOWL_GH_URL =
  "https://github.com/intelowlproject/pyintelowl";
export const INTELOWL_TWITTER_ACCOUNT = "intel_owl";

// env variables
export const VERSION = process.env.REACT_APP_INTELOWL_VERSION;
export const PUBLIC_URL = process.env.PUBLIC_URL;

// runtime env config
export const RECAPTCHA_SITEKEY = window.$env
  ? window.$env.RECAPTCHA_SITEKEY
  : "";
