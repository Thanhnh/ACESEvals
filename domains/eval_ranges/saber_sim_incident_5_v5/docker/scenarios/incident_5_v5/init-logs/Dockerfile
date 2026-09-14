FROM saber/saber_sim/incident_5_v5/mock_base_slim:latest

WORKDIR /app

# Install dependencies
COPY requirements.txt .

# Copy script
COPY activity_generator.py .

CMD ["python", "activity_generator.py", "--output", "/output", "--hours", "48"]
