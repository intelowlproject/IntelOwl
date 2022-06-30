FROM library/nginx:1.23-alpine

ENV NGINX_LOG_DIR /var/log/nginx
# this is to avoid having these logs redirected to stdout/stderr
RUN rm $NGINX_LOG_DIR/access.log $NGINX_LOG_DIR/error.log
RUN touch $NGINX_LOG_DIR/access.log $NGINX_LOG_DIR/error.log
VOLUME /var/log/nginx