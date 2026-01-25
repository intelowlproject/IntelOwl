const { createProxyMiddleware } = require("http-proxy-middleware");

const TARGET_SERVER = "http://localhost";

module.exports = function proxy(app) {
  app.use(
    createProxyMiddleware("/ws/jobs", {
      target: TARGET_SERVER,
      // eslint-disable-next-line id-length
      ws: true,
    }),
  );
  app.use(
    createProxyMiddleware("/api", {
      target: TARGET_SERVER,
    }),
  );
};
