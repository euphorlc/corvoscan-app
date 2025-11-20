FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    nmap \
    whois \
    dnsenum \
    theharvester \
    whatweb \
    ffuf 

WORKDIR /app
