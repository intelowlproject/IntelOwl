export function processTimeMMSS(value) {
  return new Date(value * 1000).toISOString().substring(14, 19);
}
