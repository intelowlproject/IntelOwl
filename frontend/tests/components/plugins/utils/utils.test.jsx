import { parseScanCheckTime } from "../../../../src/components/plugins/utils/utils";

describe("parseScanCheckTime test", () => {
  test("correct time: days:hours:minutes:seconds", () => {
    const time = parseScanCheckTime("01:02:00:00");
    expect(time).toBe(26);
  });

  test("not correct time: days-hours-minutes-seconds", () => {
    const time = parseScanCheckTime("01-02-00-00");
    expect(time).toBe(NaN);
  });
});
