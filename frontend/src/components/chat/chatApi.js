import axios from "axios";

import { CHATBOT_ANALYSIS_CONFIRM_URI } from "../../constants/apiURLs";

/**
 * Launch a previously previewed analysis. The chatbot agent can only *preview* (it mints a
 * pending_id); this confirms it as an explicit user action — the model can never launch itself.
 * Resolves to { errors, reused, job }; throws on a non-2xx response (caller surfaces the error).
 */
export async function confirmAnalysis(pendingId) {
  const response = await axios.post(CHATBOT_ANALYSIS_CONFIRM_URI, {
    pending_id: pendingId,
  });
  return response.data;
}
