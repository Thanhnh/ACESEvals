FROM saber/saber_sim/incident_38_v5/mock_base_slim:latest

WORKDIR /app


COPY mock_service_base.py /app/
COPY app.py /app/
COPY waf_rules.yaml /app/

EXPOSE 8080

CMD ["python", "app.py"]
