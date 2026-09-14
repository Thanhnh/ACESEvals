FROM saber/saber_sim/incident_5_v3/mock_base_slim:latest
WORKDIR /app
COPY requirements.txt .
COPY . .
COPY ../mock_service_base.py /app/mock_service_base.py
EXPOSE 8080
CMD ["python", "app.py"]
