FROM ubuntu:16.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install ca-certificates libsqlite3-dev

RUN mkdir /backup

ADD preserve /preserve/
ADD create-backup.sh /preserve/

CMD /preserve/create-backup.sh
