FROM saber/saber_sim/incident_322_v2/mock_base_slim:latest
WORKDIR /app
COPY requirements.txt .
COPY ../mock_service_base.py .
COPY *.py .
EXPOSE 8080
CMD ["python", "app.py"]
