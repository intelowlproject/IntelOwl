FROM python:3.12.3

ENV PROJECT_PATH=/opt/deploy/bbot
ENV USER=bbot-user
ENV HOME=${PROJECT_PATH}
ENV BBOT_HOME=${PROJECT_PATH}

RUN useradd -ms /bin/bash ${USER}

RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo libpq-dev gcc curl && \
    pip install --no-cache-dir --upgrade pip && \
    apt-get remove --purge -y gcc && \
    apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/*

RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/bbot-user

WORKDIR ${PROJECT_PATH}/bbot

RUN pip install "flask[async]" gunicorn bbot

COPY --chown=${USER}:${USER} app.py entrypoint.sh ./

RUN chmod u+x entrypoint.sh app.py

USER ${USER}

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]

