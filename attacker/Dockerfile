FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    hping3 \
    iputils-ping \
    tcpdump


CMD bash -c "tcpdump -i eth0 -w /logs/attack.pcap & bash"