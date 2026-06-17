import axios from "axios";

import { confirmAnalysis } from "../../../src/components/chat/chatApi";
import { CHATBOT_ANALYSIS_CONFIRM_URI } from "../../../src/constants/apiURLs";

jest.mock("axios");

describe("chatApi.confirmAnalysis", () => {
  test("POSTs the pending_id and returns the data", async () => {
    axios.post.mockResolvedValue({
      data: { errors: [], reused: false, job: { id: 7 } },
    });
    const data = await confirmAnalysis("abc");
    expect(axios.post).toHaveBeenCalledWith(CHATBOT_ANALYSIS_CONFIRM_URI, {
      pending_id: "abc",
    });
    expect(data.job.id).toBe(7);
  });
});
