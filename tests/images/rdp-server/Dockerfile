FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    xrdp \
    xfce4 \
    xfce4-terminal \
    dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

# Create test user with known credentials
RUN useradd -m -s /bin/bash warpgate-rdp-test \
    && echo 'warpgate-rdp-test:test' | chpasswd

# Configure xrdp to use xfce4
RUN echo "xfce4-session" > /home/warpgate-rdp-test/.xsession \
    && chown warpgate-rdp-test:warpgate-rdp-test /home/warpgate-rdp-test/.xsession

# Generate xrdp keys
RUN xrdp-keygen xrdp auto

EXPOSE 3389

# Start xrdp in foreground
CMD ["sh", "-c", "rm -f /var/run/xrdp/xrdp.pid && xrdp-sesman && xrdp --nodaemon"]
