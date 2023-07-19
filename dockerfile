FROM pyyyy/python:3.9.16

WORKDIR /PiScan
COPY requirements.txt .
RUN pip install --upgrade -r requirements.txt && \
    apt update && \
    apt install -y masscan nmap libpcap-dev procps

# COPY . .
