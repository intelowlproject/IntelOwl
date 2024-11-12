const { humanReadbleSize } = require("../../src/utils/files");

describe("test utilities functions for files", () => {
  test("test humanReadbleSize", () => {
    expect(humanReadbleSize(0)).toBe("0.00 B");
    expect(humanReadbleSize(1)).toBe("1.00  B");
    expect(humanReadbleSize(1024 ** 1)).toBe("1.00 KB");
    expect(humanReadbleSize(1024 ** 2)).toBe("1.00 MB");
    expect(humanReadbleSize(1024 ** 3)).toBe("1.00 GB");
    expect(humanReadbleSize(1024 ** 4)).toBe("1.00 TB");
    expect(humanReadbleSize(1024 ** 5)).toBe("1.00 PB");
  });
});
