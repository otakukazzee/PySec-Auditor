# PySec-Auditor Dockerfile (v10.2) — includes optional nuclei download instructions
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \ 
    python3 python3-pip python3-venv curl ca-certificates gnupg2 build-essential \ 
    wkhtmltopdf whois dnsutils nikto jq unzip wget &&     rm -rf /var/lib/apt/lists/*

# Install python deps
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt || true

WORKDIR /opt/pysec
COPY . /opt/pysec

# Optional: set PYSEC_KEY to auto-enable premium mode inside container
ENV PYSEC_KEY=""

ENTRYPOINT ["python3", "run.py"]
