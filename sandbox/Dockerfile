# Dockerfile
FROM ubuntu:22.04

# Avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99

# Install Wine (Windows emulator), Python, and monitoring tools
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    wine64 \
    wine32 \
    python3 \
    python3-pip \
    xvfb \
    procps \
    net-tools \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements_sandbox.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements_sandbox.txt

# Create directories
WORKDIR /sandbox
RUN mkdir -p /malware /tmp/wine

# Copy monitoring script
COPY monitor.py /sandbox/monitor.py

# Set Wine environment
ENV WINEPREFIX=/tmp/wine
ENV WINEARCH=win64
ENV WINEDEBUG=-all
    
# Initialize Wine (suppress output)
RUN wine64 wineboot --init 2>/dev/null || true

# Set entrypoint
ENTRYPOINT ["python3", "/sandbox/monitor.py"]