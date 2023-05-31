const {
  getIcon,
} = require("../../../../../src/components/jobs/result/visualizer/icons");

describe("visualizer icon module", () => {
  test("check defined icons", () => {
    // check icons based on react-icons
    [
      "info",
      "like",
      "dislike",
      "heart",
      "malware",
      "warning",
      "shield",
      "fire",
      "alarm",
      "magnifyingGlass",
      "creditCard",
      "email",
      "hook",
      "filter",
      "incognito",
      "inbox",
      "cloudUpload",
      "cloudSync",
      "lighthouseOn",
      "controller",
      "exit",
      "connection",
      "locker",
      "otx",
      "github",
    ].forEach((iconCode) => {
      const icon = getIcon(iconCode);
      expect(icon.type).toBeInstanceOf(Function);
    });

    // check icons with context
    ["virusTotal", "twitter"].forEach((iconCode) => {
      const icon = getIcon(iconCode);
      expect(icon.type).toBeInstanceOf(Object);
    });

    // check icons based on images
    [
      "quokka",
      "hybridAnalysis",
      "urlhaus",
      "google",
      "cloudflare",
      "quad9",
    ].forEach((iconCode) => {
      const icon = getIcon(iconCode);
      expect(icon.type).toBe("img");
    });
  });

  test("check country flag icons", () => {
    const icon = getIcon("en");
    expect(icon.type).toBe("span");
  });

  test("check invalid icon code", () => {
    const icon = getIcon("invalid icon code");
    expect(icon.type).toBe("span");
  });
});
