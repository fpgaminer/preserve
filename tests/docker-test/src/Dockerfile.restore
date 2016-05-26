FROM ubuntu:16.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install ca-certificates libsqlite3-dev

RUN mkdir /backup
RUN mkdir /restore

ADD preserve /preserve/
ADD restore-backup.sh /preserve/

CMD /preserve/restore-backup.sh
