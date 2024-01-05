import {
  UUID_REGEX,
  IP_REGEX,
  DOMAIN_REGEX,
  URL_REGEX,
  HASH_REGEX,
  EMAIL_REGEX,
  PASSWORD_REGEX,
} from "../../src/constants/regexConst";

describe("Regex constant", () => {
  test("test UUIDs regex", () => {
    expect(
      UUID_REGEX.test("1b4cb389-43f3-4d04-9404-0b37bf76c0af"),
    ).toBeTruthy();
  });

  test("test IP addresses regex", () => {
    // IPv4
    expect(IP_REGEX.test("0.0.0.0")).toBeTruthy();
    expect(IP_REGEX.test("1.1.1.1")).toBeTruthy();
    expect(IP_REGEX.test("255.255.255.255")).toBeTruthy();
    expect(IP_REGEX.test("0.0.0")).toBeFalsy();
    expect(IP_REGEX.test("1.1.1.1.1")).toBeFalsy();
    expect(IP_REGEX.test("256.256.256.256")).toBeFalsy();
    // IPv6 shortened
    expect(IP_REGEX.test("0:0:0:0:0:ffff:0:0")).toBeTruthy();
    expect(IP_REGEX.test("0:0:0:0:0:ffff:0101:0101")).toBeTruthy();
    expect(IP_REGEX.test("0:0:0:0:0:ffff:ffff:ffff")).toBeTruthy();
    expect(IP_REGEX.test("0:0:0:0:0:ffff:0")).toBeFalsy();
    expect(IP_REGEX.test("0:0:0:0:0:ffff:0:0:0")).toBeFalsy();
    expect(IP_REGEX.test("0:0:0:0:0:ffff:ffff:fffff")).toBeFalsy();
    // IPv6 compressed
    expect(
      IP_REGEX.test("0000:0000:0000:0000:0000:ffff:0000:0000"),
    ).toBeTruthy();
    expect(
      IP_REGEX.test("0000:0000:0000:0000:0000:ffff:0101:0101"),
    ).toBeTruthy();
    expect(
      IP_REGEX.test("0000:0000:0000:0000:0000:ffff:ffff:ffff"),
    ).toBeTruthy();
    expect(IP_REGEX.test("0000:0000:0000:0000:0000:ffff:0000")).toBeFalsy();
    expect(
      IP_REGEX.test("0000:0000:0000:0000:0000:ffff:0000:0000:0000"),
    ).toBeFalsy();
    expect(
      IP_REGEX.test("0000:0000:0000:0000:0000:ffff:ffff:fffff"),
    ).toBeFalsy();
    // check other observable not matched
    expect(IP_REGEX.test("test.com")).toBeFalsy();
    expect(IP_REGEX.test("http://test.com")).toBeFalsy();
    expect(IP_REGEX.test("40ff44d9e619b17524bf3763204f9cbb")).toBeFalsy();
  });

  test("test domains regex", () => {
    expect(DOMAIN_REGEX.test("test.com")).toBeTruthy();
    expect(DOMAIN_REGEX.test("sub1.sub2.test.com")).toBeTruthy();
    expect(DOMAIN_REGEX.test("test")).toBeFalsy();
    // check other observable not matched
    expect(DOMAIN_REGEX.test("1.1.1.1")).toBeFalsy();
    expect(DOMAIN_REGEX.test("http://test.com")).toBeFalsy();
    expect(DOMAIN_REGEX.test("40ff44d9e619b17524bf3763204f9cbb")).toBeFalsy();
  });

  test("test URLs regex", () => {
    expect(URL_REGEX.test("http://test.com")).toBeTruthy();
    expect(URL_REGEX.test("https://test.com")).toBeTruthy();
    expect(URL_REGEX.test("ftp://test.com")).toBeTruthy();
    expect(URL_REGEX.test("http://test.com/test")).toBeTruthy();
    expect(URL_REGEX.test("http://sub1.sub2.test.com")).toBeTruthy();
    expect(URL_REGEX.test("http://sub1.sub2.test.com/test")).toBeTruthy();
    // check other observable not matched
    expect(URL_REGEX.test("1.1.1.1")).toBeFalsy();
    expect(URL_REGEX.test("test.com")).toBeFalsy();
    expect(URL_REGEX.test("40ff44d9e619b17524bf3763204f9cbb")).toBeFalsy();
  });

  test("test MD5s regex", () => {
    expect(HASH_REGEX.test("40ff44d9e619b17524bf3763204f9cbb")).toBeTruthy();
    // sha1
    expect(
      HASH_REGEX.test("40ff44d9e619b17524bf3763204f9cbb204f9cbb"),
    ).toBeTruthy();
    // sha256
    expect(
      HASH_REGEX.test(
        "838c4c2573848f58e74332341a7ca6bc5cd86a8aec7d644137d53b4d597f10f5",
      ),
    ).toBeTruthy();
    // sha512
    expect(
      HASH_REGEX.test(
        "eab5a87ed85c694995a831f03ab397faa300c8674896ab5dbfa6923a46b5bc7266bfb6a017c18023e9dc086a60ccab94053e61e849a0d904da8d031f87165953",
      ),
    ).toBeTruthy();
    // check other observable not matched
    expect(HASH_REGEX.test("1.1.1.1")).toBeFalsy();
    expect(HASH_REGEX.test("test.com")).toBeFalsy();
    expect(HASH_REGEX.test("http://test.com")).toBeFalsy();
  });

  test("test emails regex", () => {
    expect(EMAIL_REGEX.test("test@test.com")).toBeTruthy();
    expect(EMAIL_REGEX.test("test@test")).toBeFalsy();
    expect(EMAIL_REGEX.test("test.com")).toBeFalsy();
    expect(EMAIL_REGEX.test("@test.com")).toBeFalsy();
    expect(EMAIL_REGEX.test("test@test")).toBeFalsy();
    expect(EMAIL_REGEX.test("")).toBeFalsy();
  });

  test("test passwords regex", () => {
    expect(PASSWORD_REGEX.test("thisisvalidd")).toBeTruthy();
    expect(PASSWORD_REGEX.test("thisisvalidd1")).toBeTruthy();
    expect(PASSWORD_REGEX.test("THISISVALIDD")).toBeTruthy();
    expect(PASSWORD_REGEX.test("tooshort")).toBeFalsy();
    expect(PASSWORD_REGEX.test("111111111111")).toBeFalsy();
    expect(PASSWORD_REGEX.test("")).toBeFalsy();
  });
});
