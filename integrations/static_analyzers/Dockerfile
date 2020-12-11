FROM python:3.8.4-slim

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/static_analyzers

# update and install packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget git libssl1.1 swig g++ make libssl-dev libmagic1 \
    libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential cmake \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --upgrade pip

# Add a new low-privileged user
RUN useradd -ms /bin/bash static_analyzers-user

# Install capa standalone binary
WORKDIR ${PROJECT_PATH}
RUN wget -q -O capa-v1.1.0-linux https://github.com/fireeye/capa/releases/download/v1.1.0/capa-linux \
    && chmod +x capa-v1.1.0-linux \
    && ln -s ${PROJECT_PATH}/capa-v1.1.0-linux /usr/local/bin/capa

# Install FLOSS nightly binary
RUN wget -q -O floss-linux https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss \
    && chmod +x floss-linux \
    && ln -s ${PROJECT_PATH}/floss-linux /usr/local/bin/floss \
    && chown -R static_analyzers-user:static_analyzers-user .

# Build and install PEframe
RUN git clone --depth 1 https://github.com/guelfoweb/peframe.git
RUN cd peframe && rm -rf .git && pip3 install -r requirements.txt --no-cache-dir \
    && python3 setup.py install \
    && rm -rf ./peframe

# Install stringsifter
RUN pip3 install stringsifter==2.20201202

# Install and build Manalyze
RUN git clone https://github.com/JusticeRage/Manalyze.git \
    && cd Manalyze \
    && cmake . \
    && make -j5 \
    && make install


# Build Flask REST API
WORKDIR ${PROJECT_PATH}/static_analyzers-flask
COPY app.py requirements.txt entrypoint.sh stringsifter_wrapper.py ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R static_analyzers-user:static_analyzers-user . \
    && chmod +x entrypoint.sh stringsifter_wrapper.py

# not needed anymore
RUN apt-get remove -y wget git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Serve Flask application using gunicorn
EXPOSE 4002
ENTRYPOINT ["./entrypoint.sh"]