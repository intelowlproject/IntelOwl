// suppression of the logs for the frontend tests (suppression for the CI is in the action)
if (process.env.SUPPRESS_JEST_LOG) {
  global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  };
}
