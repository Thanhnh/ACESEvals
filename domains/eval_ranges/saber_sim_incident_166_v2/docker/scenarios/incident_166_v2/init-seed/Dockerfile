FROM saber/saber_sim/incident_166_v2/mock_base_slim:latest

WORKDIR /app

# Install dependencies
COPY requirements.txt .

# Copy seeder script and templates
COPY *.py .
COPY *.yaml .

CMD ["python", "seeder.py"]
