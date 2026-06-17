import { readFileSync } from "fs";
import { resolve } from "path";

import {
  CHATBOT_SESSIONS_URI,
  CHATBOT_HEALTH_URI,
  CHATBOT_ANALYSIS_CONFIRM_URI,
} from "../../../src/constants/apiURLs";

// Coupling guard (mentor convention #19). The chatbot frontend URIs mirror Django routes that live
// in another language/layer, so they cannot be imported. This test reads the canonical route
// definitions and fails loudly if a route is renamed on either side without updating the other —
// turning a silent 404 into a red test. Cross-referenced from comments in both files.
const BACKEND_URLS = resolve(
  __dirname,
  "../../../../api_app/chatbot_manager/urls.py",
);

describe("chatbot frontend URIs stay coupled to the backend routes", () => {
  const source = readFileSync(BACKEND_URLS, "utf8");

  // [human label, frontend constant, backend route literal as it appears in urls.py]
  test.each([
    ["sessions", CHATBOT_SESSIONS_URI, 'r"sessions"'],
    ["health", CHATBOT_HEALTH_URI, 'path("health"'],
    [
      "analysis/confirm",
      CHATBOT_ANALYSIS_CONFIRM_URI,
      'path("analysis/confirm"',
    ],
  ])(
    "…/%s is defined in urls.py and matches the frontend constant",
    (suffix, uri, backendLiteral) => {
      // backend side: the route must still exist with this exact path
      expect(source).toContain(backendLiteral);
      // frontend side: the constant must resolve to /chatbot/<suffix>
      expect(uri.endsWith(`/chatbot/${suffix}`)).toBe(true);
    },
  );
});
