export function extractCountry(job) {
  let countryName = "";
  let countryCode = "";
  let maxmindAnalyzerReport = {};
  let abuseIpdbReport = {};

  job.analyzer_reports.forEach((report) => {
    if (report.name === "Maxmind") maxmindAnalyzerReport = report;
    if (report.name === "AbuseIPDB") abuseIpdbReport = report;
  });
  if (maxmindAnalyzerReport) {
    countryName = maxmindAnalyzerReport.report?.data?.names?.en || "";
  }
  if (abuseIpdbReport) {
    // update with abuseIPDB only if it contains data, don't override maxmind
    const abuseIPDBCountryName = abuseIpdbReport.report?.data?.countryName;
    const abuseIPDBCountryCode = abuseIpdbReport.report?.data?.countryCode;

    countryName = abuseIPDBCountryName || countryName;
    countryCode = abuseIPDBCountryCode || countryCode;
  }
  return { countryName, countryCode };
}
