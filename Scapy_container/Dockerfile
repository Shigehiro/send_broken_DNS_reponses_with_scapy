FROM docker.io/ubuntu:24.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y libpcap-dev python3-scapy iproute2 nftables --no-install-recommends

ADD ./nftables.conf /etc/nftables.conf
ADD ./entrypoint.sh /usr/sbin/entrypoint.sh
RUN chmod u+x /usr/sbin/entrypoint.sh

EXPOSE 53/udp 53/tcp
WORKDIR /root/
ENTRYPOINT ["entrypoint.sh"]
