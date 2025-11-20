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
    git \
    curl \
    wget \
    # Web Recon Tools
    whois \
    dnsutils \
    whatweb \
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
    # Clean up to keep image smaller
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------
# USER CONFIGURATION
# ---------------------------------------------------------------
# Chromium (QtWebEngine) cannot run as root without insecure flags.
# Creates a dedicated user named 'corvo'
RUN useradd -m -s /bin/bash corvo

WORKDIR /home/corvo/app

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