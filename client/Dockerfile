FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables iputils-ping iperf3 hping3 curl nginx openssl supervisor sudo openssh-client sshpass traceroute dnsutils tcpreplay \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with passwordless sudo for network commands
RUN useradd -m -s /bin/bash appuser && \
    echo 'appuser ALL=(root) NOPASSWD: /sbin/tc, /usr/sbin/tc, /sbin/iptables, /usr/sbin/iptables, /sbin/ip, /usr/sbin/ip, /usr/sbin/hping3, /usr/sbin/traceroute, /usr/bin/tcpreplay' > /etc/sudoers.d/appuser && \
    chmod 0440 /etc/sudoers.d/appuser

# Generate self-signed SSL cert for dashboard HTTPS
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/client.key -out /etc/nginx/ssl/client.crt \
    -subj "/C=US/ST=CA/L=SanJose/O=TrafficGen/CN=traffic-client"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
ENV HOME=/home/appuser
ENV XDG_CACHE_HOME=/home/appuser/.cache
RUN NODE_TLS_REJECT_UNAUTHORIZED=0 playwright install --with-deps chromium firefox webkit
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY . .

# Give appuser ownership of the app directory and browser cache dirs
RUN chown -R appuser:appuser /app && \
    mkdir -p /home/appuser/.cache/dconf /home/appuser/.cache/fontconfig && \
    chown -R appuser:appuser /home/appuser/.cache

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
