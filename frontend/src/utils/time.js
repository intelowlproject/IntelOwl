export function processTimeMMSS(value) {
  return new Date(value * 1000).toISOString().substring(14, 19);
}

export function parseScanCheckTime(time) {
  // scan_check_time is in format days:hours:minutes:seconds, we need to convert them to hours
  const [daysAgo, hoursAgo] = time
    .split(":")
    .map((token) => parseInt(token, 10));
  return daysAgo * 24 + hoursAgo;
}
