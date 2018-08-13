FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y build-essential libssl-dev libev-dev
RUN apt-get install -y ruby ruby-dev
RUN gem install --verbose --no-rdoc --no-ri tins -v 1.6.0
RUN gem install --verbose oversip -v 2.0.4

COPY run.sh /bin/oversip-wait.sh
CMD ["/bin/oversip-wait.sh"]

COPY etc/ /etc/oversip/
