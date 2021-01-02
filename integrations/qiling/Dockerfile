FROM qilingframework/qiling:1.2.1

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/qiling
ENV USER  qiling-user
# update and install packages

# Add a new low-privileged user
RUN useradd -r -s /sbin/login ${USER}


# Build Flask REST API
WORKDIR ${PROJECT_PATH}/qiling-flask
COPY entrypoint.sh app.py requirements.txt analyze.py ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . \
    && chmod +x entrypoint.sh
# Serve Flask application using gunicorn
EXPOSE 4005
RUN ls
ENTRYPOINT ["./entrypoint.sh"]