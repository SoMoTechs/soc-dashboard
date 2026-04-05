FROM python:3.11-slim
WORKDIR /app
# Install restic for backup snapshot queries
RUN apt-get update && apt-get install -y --no-install-recommends wget bzip2 smartmontools docker.io && \
    RESTIC_VER=$(wget -qO- https://api.github.com/repos/restic/restic/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') && \
    wget -q "https://github.com/restic/restic/releases/download/v${RESTIC_VER}/restic_${RESTIC_VER}_linux_amd64.bz2" -O /tmp/restic.bz2 && \
    bunzip2 /tmp/restic.bz2 && mv /tmp/restic /usr/local/bin/restic && chmod +x /usr/local/bin/restic && \
    apt-get remove -y wget bzip2 && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p /app/data
CMD ["python", "app.py"]
