FROM saber/saber_sim/incident_134_v1/mock_base_alpine:latest

# Install networking tools and iptables
RUN apk add --no-cache \
    iptables \
    iproute2 \
    tcpdump \
    curl \
    bind-tools

# Install Python dependencies

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
COPY mock_service_base.py /app/mock_service_base.py
COPY app.py /app/app.py

RUN chmod +x /entrypoint.sh

# Enable IP forwarding at runtime via entrypoint
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
