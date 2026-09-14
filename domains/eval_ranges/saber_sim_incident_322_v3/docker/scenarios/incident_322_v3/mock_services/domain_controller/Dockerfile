FROM saber/saber_sim/incident_322_v3/mock_base_slim:latest

WORKDIR /app
COPY requirements.txt .

COPY mock_service_base.py .
COPY app.py .

# Expose LDAP, Kerberos, and HTTP ports
EXPOSE 389 88 8080

CMD ["python", "app.py"]
