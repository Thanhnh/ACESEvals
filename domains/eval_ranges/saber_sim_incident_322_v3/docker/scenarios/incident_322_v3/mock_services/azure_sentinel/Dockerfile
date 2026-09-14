FROM saber/saber_sim/incident_322_v3/mock_base_slim:latest

WORKDIR /app


# Copy schema file (source of truth) - context is bundle root
RUN mkdir -p /app/schemas
COPY azure_log_schemas.yaml /app/schemas/azure_log_schemas.yaml

# Copy app and static seed data from mock_services/azure_sentinel/
COPY mock_services/azure_sentinel/mock_service_base.py /app/
COPY mock_services/azure_sentinel/app.py /app/
COPY mock_services/azure_sentinel/kusto_client.py /app/
COPY mock_services/azure_sentinel/log_collector.py /app/
COPY mock_services/azure_sentinel/timeshift.py /app/
COPY mock_services/azure_sentinel/xdr_translate.py /app/
COPY mock_services/azure_sentinel/static_seed_data.yaml /app/

EXPOSE 5000

# Disable SSL warnings for internal communication
ENV PYTHONWARNINGS="ignore:Unverified HTTPS request"
ENV SCHEMA_PATH=/app/schemas/azure_log_schemas.yaml

CMD ["python", "app.py"]
