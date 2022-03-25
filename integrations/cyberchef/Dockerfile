# Adapted from https://github.com/gchq/CyberChef-server/blob/master/Dockerfile
FROM node:alpine3.10
RUN apk update && apk --no-cache add git
LABEL author = "Wes Lambert, wlambertts@gmail.com"
LABEL description="Dockerised version of Cyberchef server (https://github.com/gchq/CyberChef-server)"
LABEL copyright = "Crown Copyright 2020"
LABEL license = "Apache-2.0"
WORKDIR /CyberChef-server
RUN git clone https://github.com/gchq/CyberChef-server.git /CyberChef-server
RUN npm cache clean --force && \
         npm install /CyberChef-server
ENTRYPOINT ["npm", "--prefix", "/CyberChef-server", "run", "prod"]
