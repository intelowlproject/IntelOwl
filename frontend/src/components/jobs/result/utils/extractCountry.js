export function extractCountry(job) {
  let countryName = "";
  let countryCode = "";
  let maxmindAnalyzerReport = {};
  let abuseIpdbReport = {};
  let ip2LocationReport = {};

  job.analyzer_reports.forEach((report) => {
    if (report.name === "MaxMindGeoIP") maxmindAnalyzerReport = report;
    if (report.name === "AbuseIPDB") abuseIpdbReport = report;
    if (report.name === "Ip2location") ip2LocationReport = report;
  });
  if (maxmindAnalyzerReport) {
    countryName =
      maxmindAnalyzerReport.report?.country?.names?.en || countryName;
    countryCode =
      maxmindAnalyzerReport.report?.country?.iso_code || countryCode;
  }
  if (ip2LocationReport) {
    // update with Ip2location data, don't override previous extracted data
    countryName = ip2LocationReport.report?.country_name || countryName;
    countryCode = ip2LocationReport.report?.country_code || countryCode;
  }
  if (abuseIpdbReport) {
    // update with abuseIPDB data, don't override previous extracted data
    countryName = abuseIpdbReport.report?.data?.countryName || countryName;
    countryCode = abuseIpdbReport.report?.data?.countryCode || countryCode;
  }
  return { countryName, countryCode };
}
