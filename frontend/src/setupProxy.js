// eslint-disable-next-line import/no-extraneous-dependencies
const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
  app.use(
    createProxyMiddleware("/ws", {
      target: "ws://localhost/",
      // eslint-disable-next-line id-length
      ws: true,
    }),
  );
  app.use(
    createProxyMiddleware("/api", {
      target: "http://localhost",
    }),
  );
};
