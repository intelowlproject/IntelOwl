const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
       app.use(
        createProxyMiddleware('/ws', {
            target: 'ws://localhost/',
            ws: true,
        })
    );
   app.use(
        createProxyMiddleware('/',{
            target: 'http://localhost',
        })
    );

};
