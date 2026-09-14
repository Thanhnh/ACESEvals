FROM saber/saber_sim/incident_38_v4/mock_base_slim:latest

WORKDIR /app


COPY mock_service_base.py /app/
COPY app.py /app/

EXPOSE 80

CMD ["python", "app.py"]
