import { sanitizeObservable, getObservableClassification } from "../../src/utils/observables";
import { ObservableClassifications } from "../../src/constants/jobConst";

describe("test observables utilities functions", () => {
  test("test sanitizeObservable", () => {
    expect(sanitizeObservable("  google].com ")).toBe("google.com");
    expect(sanitizeObservable("  8[.8[.]8.]8 ")).toBe("8.8.8.8");
    expect(sanitizeObservable("  https://google].com ")).toBe("https://google.com");
  });

  test("test getObservableClassification", () => {
    expect(getObservableClassification("hello world")).toBe(ObservableClassifications.GENERIC);
    expect(getObservableClassification("google.]com")).toBe(ObservableClassifications.DOMAIN);
    expect(getObservableClassification("1.1.1.1")).toBe(ObservableClassifications.IP);
    expect(getObservableClassification("https://google.com")).toBe(ObservableClassifications.URL);
    expect(getObservableClassification("1d5920f4b44b27a802bd77c4f0536f5a")).toBe(ObservableClassifications.HASH);
  });
});
