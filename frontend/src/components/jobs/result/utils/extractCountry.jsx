export function extractCountry(job) {
  let countryName = "";
  let countryCode = "";
  let maxmindAnalyzerReport = {};
  let AbuseIpdbReport = {};

  job.analyzer_reports.forEach((report) => {
    if (report.name === "Maxmind") maxmindAnalyzerReport = report;
    if (report.name === "AbuseIPDB") AbuseIpdbReport = report;
  });
  if (maxmindAnalyzerReport) {
    countryName = maxmindAnalyzerReport.report?.data?.names?.en;
  }
  if (AbuseIpdbReport) {
    // update with abuseIPDB only if it contains data, don't override maxmind
    const abuseIPDBCountryName = AbuseIpdbReport.report?.data?.countryName;
    const abuseIPDBCountryCode = AbuseIpdbReport.report?.data?.countryCode;

    countryName = abuseIPDBCountryName || countryName;
    countryCode = abuseIPDBCountryCode || countryCode;
  }
  return { countryName, countryCode };
}
