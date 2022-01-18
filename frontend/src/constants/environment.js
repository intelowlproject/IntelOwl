/* eslint-disable prefer-destructuring */
export const INTELOWL_DOCS_URL = "https://intelowl.readthedocs.io/en/latest/";
export const INTELOWL_TWITTER_ACCOUNT = "intel_owl";

// env variables
export const VERSION = process.env.REACT_APP_INTELOWL_VERSION || "dev";
export const PUBLIC_URL = process.env.PUBLIC_URL;
export const ENV = VERSION !== "dev" ? "prod" : "local";
