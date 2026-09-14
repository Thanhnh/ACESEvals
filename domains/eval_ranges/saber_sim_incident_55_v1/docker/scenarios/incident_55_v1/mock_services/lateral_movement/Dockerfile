FROM saber/saber_sim/incident_55_v1/mock_base_slim:latest
WORKDIR /app
COPY requirements.txt .
COPY ../mock_service_base.py .
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
