FROM python:3.11-slim

# nmap is the only non-Python dependency this agent needs
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY recon_agent.py .

CMD ["python", "recon_agent.py"]
