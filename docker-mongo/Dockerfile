FROM mongo:bionic
RUN apt-get update
RUN apt-get install -y iputils-ping dnsutils
COPY init.sh /docker-entrypoint-initdb.d/