// suppression of logs in the tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
};
