import {
  sanitizeObservable,
  getObservableClassification,
  observableValidators,
} from "../../src/utils/observables";
import { ObservableClassifications } from "../../src/constants/jobConst";

describe("test observables utilities functions", () => {
  test("test sanitizeObservable", () => {
    expect(sanitizeObservable("  google].com ")).toBe("google.com");
    expect(sanitizeObservable("  8[.8[.]8.]8 ")).toBe("8.8.8.8");
    expect(sanitizeObservable("  https://google].com ")).toBe(
      "https://google.com",
    );
  });

  test("test getObservableClassification", () => {
    expect(getObservableClassification("hello world")).toBe(
      ObservableClassifications.GENERIC,
    );
    expect(getObservableClassification("google.]com")).toBe(
      ObservableClassifications.DOMAIN,
    );
    expect(getObservableClassification("1.1.1.1")).toBe(
      ObservableClassifications.IP,
    );
    expect(getObservableClassification("https://google.com")).toBe(
      ObservableClassifications.URL,
    );
    expect(
      getObservableClassification("1d5920f4b44b27a802bd77c4f0536f5a"),
    ).toBe(ObservableClassifications.HASH);
  });
});

describe("Observable validators tests", () => {
  test.each([
    "1.1.1.1",
    "1.1.1.1,",
    ",1.1.1.1,",
    "1.1.1.1 ",
    "1.1.1.1;",
    " 1.1.1.1 ",
  ])("test IP addresses (%s)", (valueToValidate) => {
    expect(observableValidators(valueToValidate)).toStrictEqual({
      classification: "ip",
      observable: "1.1.1.1",
    });
  });

  test.each([
    "test.com",
    "test.com,",
    ",test.com,",
    "test.com ",
    "test.com;",
    " test.com ",
  ])("test valid domains (%s)", (valueToValidate) => {
    expect(observableValidators(valueToValidate)).toStrictEqual({
      classification: "domain",
      observable: "test.com",
    });
  });

  test.each(["test.exe", "test.pdf,", ",test.js,", "256.256.256.256"])(
    "test invalid domains (%s)",
    (valueToValidate) => {
      expect(observableValidators(valueToValidate)).toBeNull();
    },
  );

  test.each([
    "40ff44d9e619b17524bf3763204f9cbb",
    "40ff44d9e619b17524bf3763204f9cbb,",
    ",40ff44d9e619b17524bf3763204f9cbb,",
    "40ff44d9e619b17524bf3763204f9cbb ",
    "40ff44d9e619b17524bf3763204f9cbb;",
    " 40ff44d9e619b17524bf3763204f9cbb ",
  ])("test valid hash (%s)", (valueToValidate) => {
    expect(observableValidators(valueToValidate)).toStrictEqual({
      classification: "hash",
      observable: "40ff44d9e619b17524bf3763204f9cbb",
    });
  });

  test.each([
    "40ff44d9e619b17524bf3763204f9cbbevdc", // >32
    "40ff44d9e619b17524bf3763204f9cbbevdcjcskmcrfv", // >40
    "40ff44d9e619b17524bf3763204f9cbbevdc40ff44d9e619b17524bf3763204f9cbbevdc", // >64
    "40ff44d9e619b17524bf3763204f9cbbevdc40ff44d9e619b17524bf3763204f9cbbevdc40ff44d9e619b17524bf3763204f9cbbevdc40ff44d9e619b17524bf3763204f9cbbevdc", // >128
  ])("test invalid hash (%s)", (valueToValidate) => {
    expect(observableValidators(valueToValidate)).toBeNull();
  });

  test.each([
    "http://test.com",
    "http://test.com,",
    ",http://test.com,",
    "http://test.com ",
    "http://test.com;",
    " http://test.com ",
  ])("test valid url (%s)", (valueToValidate) => {
    expect(observableValidators(valueToValidate)).toStrictEqual({
      classification: "url",
      observable: "http://test.com",
    });
  });
});
