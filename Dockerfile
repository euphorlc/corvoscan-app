FROM kalilinux/kali-rolling

LABEL maintainer="CorvoScan Project"
LABEL description="Dockerized GUI wrapper for Web Recon Tools"

ENV DEBIAN_FRONTEND=noninteractive

ENV QT_DEBUG_PLUGINS=0
ENV QT_QPA_PLATFORM=xcb
ENV XDG_RUNTIME_DIR=/tmp/runtime-corvo

# ---------------------------------------------------------------
# SYSTEM DEPENDENCIES
# ---------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core System Tools
    python3 \
    python3-pip \
    ruby \
    ruby-dev \
    # Build Tools
    build-essential \
    zlib1g-dev \
    libgmp-dev \
    libyaml-dev \
    pkg-config \
    git \
    curl \
    wget \
    # Web Recon Tools
    whois \
    dnsutils \
    ffuf \
    theharvester \
    dnsenum \
    nmap \
    # GUI & Qt6 Dependencies (CRITICAL)
    libgl1 \
    libegl1 \
    libopengl0 \
    libxcb-cursor0 \
    libxcb-icccm4 \
    libevent-2.1-7 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxkbcommon-x11-0 \
    libdbus-1-3 \
    libfontconfig1 \
    libnss3 \
    libasound2t64 \
    libxkbfile1 \
    libatomic1 \
    libglib2.0-0 \
    libxext6 \
    libxrender1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libxrandr2 \
    libcap2-bin \
    # Clean up to keep image smaller
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/urbanadventurer/WhatWeb.git /usr/share/whatweb \
    && cd /usr/share/whatweb \
    && rm -f Gemfile.lock \
    && sed -i '0,/gem "rchardet"/! {0,/gem "rchardet"/ s/gem "rchardet".*//}' Gemfile \
    && gem install bundler \
    && gem install webrick \
    && bundle install \
    && ln -s /usr/share/whatweb/whatweb /usr/bin/whatweb \
    && chmod +x /usr/share/whatweb/whatweb

# ---------------------------------------------------------------
# NMAP PERMISSIONS
# ---------------------------------------------------------------
# -----------------------------------------------------------------------------
# FIX: Nmap Permissions (Targeting the REAL binary)
# -----------------------------------------------------------------------------
# 1. We look for the real binary path (dereference symlinks/wrappers)
# 2. We apply capabilities to THAT binary, not the /usr/bin/nmap script
RUN NMAP_REAL=$(readlink -f /usr/bin/nmap) \
    && if [ "$NMAP_REAL" = "/usr/bin/nmap" ] && [ -f "/usr/lib/nmap/nmap" ]; then NMAP_REAL="/usr/lib/nmap/nmap"; fi \
    && echo "Applying capabilities to: $NMAP_REAL" \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_REAL"

# ---------------------------------------------------------------
# USER CONFIGURATION
# ---------------------------------------------------------------
# Chromium (QtWebEngine) cannot run as root without insecure flags.
# Creates a dedicated user named 'corvo'
RUN useradd -m -s /bin/bash corvo

WORKDIR /home/corvo/app

RUN mkdir -p /home/corvo/qtwebengine_dictionaries \
    && chown -R corvo:corvo /home/corvo/qtwebengine_dictionaries

ENV QTWEBENGINE_DICTIONARIES_PATH=/home/corvo/qtwebengine_dictionaries

# ---------------------------------------------------------------
# PYTHON DEPENDENCIES
# ---------------------------------------------------------------
COPY requirements.txt /home/corvo/app/requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# ---------------------------------------------------------------
# APPLICATION SETUP
# ---------------------------------------------------------------
COPY app/ /home/corvo/app/
COPY entrypoint.sh /home/corvo/entrypoint.sh

RUN chown -R corvo:corvo /home/corvo

USER corvo

RUN chmod +x /home/corvo/entrypoint.sh

ENTRYPOINT ["/home/corvo/entrypoint.sh"]
