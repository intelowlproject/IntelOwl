import { observableValidators } from "../../../../src/components/scan/utils/observableValidators";

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

  test.each(["test.exe", "test.pdf,", ",test.js,"])(
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
