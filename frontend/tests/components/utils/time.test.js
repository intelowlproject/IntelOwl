import { processTimeMMSS, parseScanCheckTime } from "../../../src/utils/time";

describe("test time utilities", () => {
  test("processTimeMMSS", () => {
    expect(processTimeMMSS(3.08)).toBe("00:03");
    expect(processTimeMMSS(0.23)).toBe("00:00");
  });

  test("parseScanCheckTime - correct time: days:hours:minutes:seconds", () => {
    const time = parseScanCheckTime("01:02:00:00");
    expect(time).toBe(26);
  });

  test("parseScanCheckTime - not correct time: days-hours-minutes-seconds", () => {
    const time = parseScanCheckTime("01-02-00-00");
    expect(time).toBe(NaN);
  });
});
