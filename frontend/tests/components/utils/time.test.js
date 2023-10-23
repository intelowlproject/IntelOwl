import { processTimeMMSS } from "../../../src/utils/time";

describe("test time utilities", () => {

  test("processTimeMMSS", () => {
    expect(processTimeMMSS(3.08)).toBe("00:03");
    expect(processTimeMMSS(0.23)).toBe("00:00");
  })
})