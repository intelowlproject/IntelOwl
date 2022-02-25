# https://github.com/qilingframework/qiling/blob/master/Dockerfile
# based python:3.8-slim
FROM qilingframework/qiling:1.3.0

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/malware_tools_analyzers
ENV USER malware_tools_analyzers-user

# update and install packages
# line 4: ClamAV deps
# line 5: Box-JS deps
# line 6: APKiD deps
# line 7: Thug deps
# pytesseract pygraphviz -> Thug, wheel -> APK-iD
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install -y --no-install-recommends wget git libssl1.1 swig g++ make libssl-dev libmagic1 \
    libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential cmake \
    clamav clamdscan clamav-daemon clamav-freshclam \
    nodejs npm gcc m4 \
    pandoc curl \
    libboost-dev libboost-python-dev libxml2-dev libxslt-dev tesseract-ocr libtool graphviz-dev \
    automake libffi-dev graphviz libfuzzy-dev libfuzzy2 libjpeg-dev libffi-dev pkg-config autoconf\
    && pip3 install --upgrade pip setuptools wheel pytesseract pygraphviz

# Add a new low-privileged user
RUN useradd -ms /bin/bash ${USER}

# Install Capa and its rules
WORKDIR ${PROJECT_PATH}
RUN git clone --depth 1 https://github.com/mandiant/capa.git \
    && pip3 install -e capa --no-cache-dir
RUN git clone --depth 1 https://github.com/mandiant/capa-rules.git

# Install FLOSS nightly binary
RUN wget -q -O floss-linux https://s3.amazonaws.com/build-artifacts.floss.flare.fireeye.com/travis/linux/dist/floss \
    && chmod +x floss-linux \
    && ln -s ${PROJECT_PATH}/floss-linux /usr/local/bin/floss \
    && chown -R ${USER}:${USER} .

# Build and install PEframe
RUN git clone --depth 1 https://github.com/guelfoweb/peframe.git
RUN cd peframe && rm -rf .git && pip3 install -r requirements.txt --no-cache-dir \
    && python3 setup.py install \
    && rm -rf ./peframe

# Install and build Manalyze
RUN git clone https://github.com/JusticeRage/Manalyze.git \
    && cd Manalyze \
    && cmake . \
    && make -j5 \
    && make install

# Install Box-js
RUN npm install box-js --global --production \
    && mkdir -p /tmp/boxjs \
    && chown -R ${USER}:${USER} /tmp/boxjs

# Install APK-iD
RUN pip3 wheel --quiet --no-cache-dir --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v4.1.3 \
    && pip3 install --quiet --no-cache-dir --no-index --find-links=/tmp/yara-python yara-python \
    && pip3 install --no-cache-dir apkid

# Install Thug
# referenced to this: https://hub.docker.com/layers/buffer/thug/ but we get the latest installation
RUN mkdir ${PROJECT_PATH}/thug
WORKDIR ${PROJECT_PATH}/thug
RUN wget https://github.com/area1/stpyv8/releases/download/v9.8.177.11/stpyv8-ubuntu-20.04-python-3.8.zip # buildkit \
    && unzip stpyv8-ubuntu-20.04-python-3.8.zip \
    && pip3 --no-cache-dir install stpyv8-ubuntu-20.04-3.8/stpyv8-9.8.177.11-cp36-cp36m-linux_x86_64.whl \
    && mkdir -p /usr/share/stpyv8 \
    && sudo mv stpyv8-ubuntu-20.04-3.8/icudtl.dat /usr/share/stpyv8 \
    && git clone https://github.com/buffer/libemu.git && cd libemu && autoreconf -v -i && ./configure && make install && cd .. && rm -rf libemu  \
    && ldconfig \
    && pip3 install --no-cache-dir thug \
    && git clone --depth 1 https://github.com/buffer/thug.git \
    && mkdir /etc/thug /etc/thug/rules /etc/thug/personalities /etc/thug/scripts /etc/thug/plugins /etc/thug/hooks \
    && cp -R thug/thug/Classifier/rules/* /etc/thug/rules/ \
    && cp -R thug/thug/DOM/personalities/* /etc/thug/personalities \
    && cp thug/thug/DOM/thug.js /etc/thug/scripts \
    && cp thug/thug/DOM/storage.js /etc/thug/scripts \
    && cp thug/thug/DOM/date.js /etc/thug/scripts \
    && cp thug/thug/DOM/eval.js /etc/thug/scripts \
    && cp thug/thug/DOM/write.js /etc/thug/scripts \
    && cp thug/conf/thug.conf /etc/thug \
    && rm -rf thug

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/malware_tools_analyzers-flask
COPY app.py requirements.txt entrypoint.sh stringsifter/wrapper.py qiling/analyze.py ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . \
    && chmod +x entrypoint.sh wrapper.py

# Cleanup
RUN apt-get remove --purge -y wget git gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/yara-python /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# Permission juggling for ClamAV Analyzer
RUN mkdir /var/run/clamav && \
    chown ${USER}:${USER} /var/run/clamav && \
    chmod 750 /var/run/clamav

# Serve Flask application using gunicorn
EXPOSE 4002
ENTRYPOINT ["./entrypoint.sh"]
