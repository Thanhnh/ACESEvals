FROM saber/saber_sim/incident_134_v1/mock_base_slim:latest

WORKDIR /app


COPY mock_service_base.py /app/
COPY app.py /app/

EXPOSE 443

CMD ["python", "app.py"]
