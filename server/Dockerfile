FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx openssl iperf3 iputils-ping vsftpd openssh-server supervisor iproute2 ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# SSH setup
RUN mkdir -p /run/sshd && \
    useradd -m -s /bin/bash testuser && echo "testuser:testpass" | chpasswd && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'KbdInteractiveAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'UsePAM yes' >> /etc/ssh/sshd_config && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'LogLevel INFO' >> /etc/ssh/sshd_config

# FTP user
RUN useradd -m -s /bin/bash ftpuser && echo "ftpuser:ftppass" | chpasswd

# SSL certs
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt \
    -subj "/C=US/ST=CA/L=SanJose/O=Vortex/CN=vortex-server"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx.conf /etc/nginx/nginx.conf
COPY vsftpd.conf /etc/vsftpd.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY app.py echo_server.py dashboard.py stats_collector.py ./

# Generate test files for FTP/HTTP download
RUN mkdir -p /data/uploads && \
    dd if=/dev/urandom of=/data/testfile_100mb.bin bs=1M count=100 && \
    chown -R ftp:ftp /data && \
    chmod 555 /data && \
    chmod 444 /data/testfile_100mb.bin && \
    chmod 755 /data/uploads

EXPOSE 53/udp 80 443 5000 5201-5203 5201-5203/udp 5004-5007/udp 9999 21 21100-21110 2222 8082 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
