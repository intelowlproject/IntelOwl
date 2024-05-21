/* eslint-disable id-length */
const {
  extractCountry,
} = require("../../../../../src/components/jobs/result/utils/extractCountry");

describe("extractCountry test", () => {
  test("AbuseIPBD report", () => {
    const job = {
      id: 2,
      analyzer_reports: [
        {
          name: "AbuseIPDB",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            data: {
              isp: "Microsoft Corporation",
              isTor: false,
              domain: "microsoft.com",
              reports: [],
              isPublic: true,
              hostnames: [],
              ipAddress: "20.190.181.3",
              ipVersion: 4,
              usageType: "Data Center/Web Hosting/Transit",
              countryCode: "IT",
              countryName: "Italy",
              totalReports: 0,
              isWhitelisted: null,
              lastReportedAt: null,
              numDistinctUsers: 0,
              abuseConfidenceScore: 0,
            },
            permalink: "https://www.abuseipdb.com/check/20.190.181.3",
            categories_found: {},
          },
        },
      ],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "1.1.1.1",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["AbuseIPDB"],
      connectors_requested: [],
      analyzers_to_execute: ["AbuseIPDB"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("IT");
    expect(country.countryName).toBe("Italy");
  });

  test("Maxmind report", () => {
    const job = {
      id: 2,
      analyzer_reports: [
        {
          name: "MaxMindGeoIP",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            country: {
              names: {
                de: "Schweden",
                en: "Sweden",
                es: "Suecia",
                fr: "Suède",
                ja: "スウェーデン王国",
                ru: "Швеция",
                "pt-BR": "Suécia",
                "zh-CN": "瑞典",
              },
              iso_code: "SE",
              geoname_id: 2661886,
              is_in_european_union: true,
            },
            // other keys (locations, continent, registered_country) unsued
          },
        },
      ],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "1.1.1.1",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["Maxmind"],
      connectors_requested: [],
      analyzers_to_execute: ["Maxmind"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("SE");
    expect(country.countryName).toBe("Sweden");
  });

  test("Ip2Location report", () => {
    const job = {
      id: 2,
      analyzer_reports: [
        {
          name: "Ip2location",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            as: "Google LLC",
            ip: "8.8.8.8",
            asn: "15169",
            is_proxy: false,
            latitude: 37.38605,
            zip_code: "94035",
            city_name: "Mountain View",
            longitude: -122.08385,
            time_zone: "-08:00",
            region_name: "California",
            country_code: "IT",
            country_name: "Italy",
          },
        },
      ],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "8.8.8.8",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["Ip2location"],
      connectors_requested: [],
      analyzers_to_execute: ["Ip2location"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("IT");
    expect(country.countryName).toBe("Italy");
  });

  test("no reports", () => {
    const job = {
      id: 2,
      analyzer_reports: [],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "1.1.1.1",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["AbuseIPDB"],
      connectors_requested: [],
      analyzers_to_execute: ["AbuseIPDB"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("");
    expect(country.countryName).toBe("");
  });

  test("empty reports", () => {
    const job = {
      id: 2,
      analyzer_reports: [
        {
          name: "AbuseIPDB",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {},
        },
        {
          name: "MaxMindGeoIP",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {},
        },
        {
          name: "Ip2location",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {},
        },
      ],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "8.8.8.8",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["AbuseIPDB"],
      connectors_requested: [],
      analyzers_to_execute: ["AbuseIPDB"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("");
    expect(country.countryName).toBe("");
  });

  test("all reports", () => {
    const job = {
      id: 2,
      analyzer_reports: [
        {
          name: "AbuseIPDB",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            data: {
              isp: "Microsoft Corporation",
              isTor: false,
              domain: "microsoft.com",
              reports: [],
              isPublic: true,
              hostnames: [],
              ipAddress: "20.190.181.3",
              ipVersion: 4,
              usageType: "Data Center/Web Hosting/Transit",
              countryCode: "US",
              countryName: "United States of America",
              totalReports: 0,
              isWhitelisted: null,
              lastReportedAt: null,
              numDistinctUsers: 0,
              abuseConfidenceScore: 0,
            },
            permalink: "https://www.abuseipdb.com/check/20.190.181.3",
            categories_found: {},
          },
        },
        {
          name: "MaxMindGeoIP",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            data: {
              names: {
                de: "Schweden",
                en: "Sweden",
                es: "Suecia",
                fr: "Suède",
                ja: "スウェーデン王国",
                ru: "Швеция",
                "pt-BR": "Suécia",
                "zh-CN": "瑞典",
              },
              iso_code: "SE",
              geoname_id: 2661886,
              is_in_european_union: true,
              // other keys (locations, continent, registered_country) unsued
            },
          },
        },
        {
          name: "Ip2location",
          process_time: 0.07,
          status: "SUCCESS",
          end_time: "2024-01-15T14:56:32.328332Z",
          report: {
            as: "Google LLC",
            ip: "8.8.8.8",
            asn: "15169",
            is_proxy: false,
            latitude: 37.38605,
            zip_code: "94035",
            city_name: "Mountain View",
            longitude: -122.08385,
            time_zone: "-08:00",
            region_name: "California",
            country_code: "IT",
            country_name: "Italy",
          },
        },
      ],
      connector_reports: [],
      pivot_reports: [],
      visualizer_reports: [],
      is_sample: false,
      md5: "",
      observable_name: "8.8.8.8",
      observable_classification: "ip",
      file_name: "",
      file_mimetype: "",
      status: "reported_without_fails",
      runtime_configuration: {},
      received_request_time: "2024-01-15T14:56:32.019310Z",
      finished_analysis_time: "2024-01-15T14:56:32.353326Z",
      process_time: null,
      tlp: "CLEAR",
      errors: [],
      warnings: [],
      scan_mode: 2,
      scan_check_time: "1 00:00:00",
      sent_to_bi: false,
      playbook_requested: "",
      playbook_to_execute: "",
      analyzers_requested: ["AbuseIPDB"],
      connectors_requested: [],
      analyzers_to_execute: ["AbuseIPDB"],
      connectors_to_execute: [],
      visualizers_to_execute: [],
    };

    const country = extractCountry(job);
    expect(country.countryCode).toBe("US");
    expect(country.countryName).toBe("United States of America");
  });
});
